"""
Wazuh Rule Validator Agent
Validates generated Wazuh XML rules against XML syntax, parent rules, decoder fields.

FIX (2026-07): `is_new_rule_type` previously decided Bootstrap Mode purely from
whether the caller's single collapsed `original_decoder` string equaled
"unknown". Since the classifier used to derive that string from `category`
only (ignoring `service`), a rule like product=linux/service=auditd produced
decoder="unknown" and triggered Bootstrap even though "linux + auditd" is a
completely ordinary, already-supported logsource.

FIX (2026-07, round 2): a second false-Bootstrap source was found. Retrieval
would correctly find the *parent* decoder (e.g. `auditd`), but the parent
decoder legitimately has zero `extracted_fields` — field extraction lives on
its children (`auditd-syscall`, `auditd-execve`, ...). The old logic read
"decoder found, but 0 fields" as "useless decoder" and forced Bootstrap Mode.

This version:
  - Moves ALL decoder resolution (including parent/child search) into the
    retrieval pipeline (see retrieval.resolve_decoder). This method's only
    job is to combine the resolution outcome with parent-rule / relevance
    signals to decide Bootstrap.
  - Bootstrap now fires ONLY when there is truly nothing usable: no direct
    decoder match, no child decoder, and no field-compatible candidate
    anywhere in the parent/child tree.
  - Field validation (`_validate_decoder_fields`) now uses semantic field
    matching (normalization + alias groups + substring fallback) instead of
    strict string equality, so a Sigma field like `key` correctly matches a
    decoder field like `audit.key`, and `CommandLine` matches `cmd` /
    `process.command_line`, etc.

FIX (2026-07, round 3): field compatibility was still purely *generic*
(normalization + a handful of curated alias groups + substring fallback).
That breaks down for cross-platform rules, where the correct Sigma -> Wazuh
field name depends on *which decoder parsed the event*, not just the field
name in isolation. For example, Sigma's "CommandLine" on Linux/auditd should
match "audit.execve.a0".."a7" (the exploded execve argv, which reconstructs
into a full command line) — a relationship no amount of string-similarity
heuristics would ever discover, and one that is actively wrong to apply to
e.g. Windows/sysmon.

This adds SIGMA_TO_WAZUH_FIELD_MAP: a curated (platform, decoder) ->
Sigma-field -> [wazuh fields] table, consulted by `fields_compatible()` /
`field_compatibility_score()` *before* falling back to the generic
normalize/alias/substring heuristics whenever a platform + decoder_name
context is supplied. Without context, behavior is unchanged from before.
"""

import re
import fnmatch
import xml.etree.ElementTree as ET
from langchain_core.documents import Document
from utils import build_chroma_filter
from logger import setup_logger

logger = setup_logger("validator", level="INFO")


# =============================================================================
# Semantic field matching
# =============================================================================
# Field names differ across Sigma sources and Wazuh decoders even when they
# refer to the same underlying value (Sigma's "Image" vs a decoder's "exe" vs
# "process.executable"). Matching must not depend on string equality alone.

FIELD_ALIASES: list[set[str]] = [
    {"image", "exe", "executable", "process.executable", "process.name", "processname", "processpath"},
    {"commandline", "cmd", "command_line", "process.command_line", "cmdline"},
    {"key", "audit.key", "auditkey", "audit_key"},
    {"user", "username", "user.name", "targetusername", "subjectusername", "account"},
    {"parentimage", "parent.exe", "parentprocessname", "parentprocesspath"},
    {"hashes", "hash", "md5", "sha1", "sha256", "filehash"},
    {"sourceip", "srcip", "src_ip", "source.ip"},
    {"destinationip", "dstip", "dst_ip", "destination.ip"},
    {"processid", "pid", "process.pid"},
    {"parentprocessid", "ppid", "parent.pid"},
]


def normalize_field(name: str) -> str:
    """Lowercase and strip everything but letters/digits, so 'audit.key',
    'Audit_Key' and 'auditkey' all compare equal."""
    return re.sub(r'[^a-z0-9]', '', name.lower())


def _alias_group_for(name: str) -> set[str] | None:
    norm = normalize_field(name)
    for group in FIELD_ALIASES:
        if any(normalize_field(g) == norm for g in group):
            return group
    return None


# =============================================================================
# Platform/decoder-aware semantic field mapping
# =============================================================================
# Keyed by the exact Sigma field name. Each value is a dict of
# (platform_pattern, decoder_name_pattern) -> [candidate Wazuh field names].
#
# Patterns support glob-style wildcards via fnmatch:
#   - platform_pattern: "windows" / "linux" / ... or "*" (any platform)
#   - decoder_pattern:  "*sysmon*" / "*auditd*" / ... or "*" (any decoder)
#
# A sigma field may appear under several different (platform, decoder)
# contexts — e.g. "Image" means something different parsed by Windows Sysmon
# vs. Linux auditd vs. macOS unified logging. All such contexts live under
# ONE top-level key here (never repeated), since a duplicated dict key would
# silently discard all but the last definition.
#
# This table is intentionally curated, not exhaustive — expand as new
# platforms/decoders are onboarded. Lookups that miss here fall back to the
# generic normalize/alias/substring heuristics in fields_compatible().
SIGMA_TO_WAZUH_FIELD_MAP: dict[str, dict[tuple[str, str], list[str]]] = {
    # ---- Windows / Sysmon / Security -----------------------------------
    "Image": {
        ("windows", "*sysmon*"): ["eventdata.image", "image", "file.name", "process.name"],
        ("windows", "*security*"): ["process.name", "executable", "target.process.name"],
        ("linux", "*auditd*"): ["audit.exe", "audit.comm", "exe", "process.name", "command"],
        ("linux", "*"): ["exe", "process.name", "command"],
        ("linux", "*syslog*"): ["command", "process.name", "exe"],
        ("macos", "*"): ["process.name", "process.path", "exe"],
    },
    "CommandLine": {
        ("windows", "*sysmon*"): ["eventdata.commandLine", "commandline", "process.command_line", "process.args"],
        ("windows", "*security*"): ["process.args", "command", "process.command_line"],
        ("linux", "*auditd*"): [
            "audit.command",
            "audit.execve.a0", "audit.execve.a1", "audit.execve.a2", "audit.execve.a3",
            "audit.execve.a4", "audit.execve.a5", "audit.execve.a6", "audit.execve.a7",
            "audit.execve.a0-a7",  # reconstructed full argv, treated as a full match
            "process.args", "command", "audit.args",
        ],
        ("linux", "*syslog*"): ["command", "process.args"],
        ("macos", "*"): ["process.args", "command"],
    },
    "ParentImage": {
        ("windows", "*sysmon*"): ["eventdata.parentImage", "parent.image", "parent.process.name"],
        ("linux", "*auditd*"): ["audit.ppid"],  # indirect via parent process lookup
    },
    "ParentCommandLine": {
        ("windows", "*sysmon*"): ["eventdata.parentCommandLine", "parent.commandline", "parent.process.args"],
    },
    "User": {
        ("windows", "*"): ["eventdata.user", "user.name", "target.user", "actor.user"],
        ("windows", "*sysmon*"): ["eventdata.user", "user.name"],
        ("linux", "*auditd*"): ["audit.auid", "audit.uid", "user.name", "actor.user"],
        ("linux", "*"): ["user.name", "uid", "auid"],
    },
    "CurrentDirectory": {
        ("windows", "*sysmon*"): ["eventdata.currentDirectory", "process.working_directory"],
        ("linux", "*auditd*"): ["audit.cwd", "process.working_directory"],
    },
    "OriginalFileName": {
        ("windows", "*sysmon*"): ["eventdata.originalFileName", "file.original_name"],
    },
    "TargetFilename": {
        ("windows", "*sysmon*"): ["eventdata.targetFilename", "file.target", "target.file.name"],
    },
    "SourceIp": {
        ("windows", "*"): ["srcip", "source.ip", "eventdata.sourceIp"],
    },
    "DestinationIp": {
        ("windows", "*"): ["dstip", "destination.ip", "eventdata.destinationIp"],
    },
    "SourcePort": {
        ("windows", "*"): ["srcport", "source.port"],
    },
    "DestinationPort": {
        ("windows", "*"): ["dstport", "destination.port"],
    },
    "Protocol": {
        ("windows", "*"): ["protocol", "network.protocol"],
    },
    "Initiated": {
        ("windows", "*sysmon*"): ["eventdata.initiated", "network.initiated"],
    },

    # ---- Web / Apache / Nginx / IIS -------------------------------------
    "c-uri": {
        ("web", "*"): ["url", "request.uri", "http.uri"],
    },
    "c-useragent": {
        ("web", "*"): ["user_agent", "http.useragent"],
    },
    "sc-status": {
        ("web", "*"): ["status", "http.status_code"],
    },
    "src_ip": {
        ("web", "*"): ["srcip", "source.ip", "client.ip"],
    },

    # ---- AWS CloudTrail --------------------------------------------------
    "eventName": {
        ("aws", "*cloudtrail*"): ["aws.eventName", "event.name", "eventName"],
    },
    "eventSource": {
        ("aws", "*cloudtrail*"): ["aws.eventSource", "event.source"],
    },
    "userIdentity.type": {
        ("aws", "*cloudtrail*"): ["aws.userIdentity.type", "user.type"],
    },
    "userIdentity.arn": {
        ("aws", "*cloudtrail*"): ["aws.userIdentity.arn", "user.arn"],
    },
    "requestParameters": {
        ("aws", "*cloudtrail*"): ["aws.requestParameters", "request.params"],
    },
    "responseElements": {
        ("aws", "*cloudtrail*"): ["aws.responseElements", "response.params"],
    },
    "errorCode": {
        ("aws", "*cloudtrail*"): ["aws.errorCode", "error.code"],
    },

    # ---- Okta --------------------------------------------------------------
    "eventType": {
        ("okta", "*"): ["okta.eventType", "event.type"],
    },
    "outcome.result": {
        ("okta", "*"): ["okta.outcome.result", "outcome.result"],
    },
    "actor.displayName": {
        ("okta", "*"): ["okta.actor.displayName", "actor.name"],
    },
    "client.ipAddress": {
        ("okta", "*"): ["srcip", "client.ip", "source.ip"],
    },

    # ---- Kubernetes ----------------------------------------------------
    "verb": {
        ("kubernetes", "*"): ["kubernetes.audit.verb", "audit.verb"],
    },
    "objectRef.resource": {
        ("kubernetes", "*"): ["kubernetes.audit.objectRef.resource", "resource.name"],
    },
    "objectRef.namespace": {
        ("kubernetes", "*"): ["kubernetes.audit.objectRef.namespace", "namespace"],
    },
    "user.username": {
        ("kubernetes", "*"): ["kubernetes.audit.user.username", "user.name"],
    },
    "responseStatus.code": {
        ("kubernetes", "*"): ["kubernetes.audit.responseStatus.code", "response.code"],
    },

    # ---- Generic / fallback (any platform, any decoder) ------------------
    "TargetObject": {
        ("*", "*"): ["target_object", "registry.value", "object.name"],
    },
    "Details": {
        ("*", "*"): ["details", "registry.data", "change.data"],
    },
    "ObjectName": {
        ("*", "*"): ["object.name", "target_object", "file.name"],
    },
    "AccessMask": {
        ("*", "*"): ["access.mask", "permissions"],
    },
    "Properties": {
        ("*", "*"): ["properties", "change.properties"],
    },
}


def _platform_matches(pattern: str, platform: str | None) -> bool:
    if not platform:
        return pattern == "*"
    return pattern == "*" or pattern.lower() == platform.lower()


def _decoder_matches(pattern: str, decoder_name: str | None) -> bool:
    if not decoder_name:
        return pattern == "*"
    return fnmatch.fnmatch(decoder_name.lower(), pattern.lower())


def _find_sigma_map_key(sigma_field: str) -> str | None:
    """Look up sigma_field in SIGMA_TO_WAZUH_FIELD_MAP, tolerant of casing/
    punctuation differences (Sigma rules aren't always cased identically to
    the map's keys)."""
    if sigma_field in SIGMA_TO_WAZUH_FIELD_MAP:
        return sigma_field
    norm = normalize_field(sigma_field)
    for key in SIGMA_TO_WAZUH_FIELD_MAP:
        if normalize_field(key) == norm:
            return key
    return None


def get_wazuh_field_candidates(sigma_field: str, platform: str | None, decoder_name: str | None) -> list[str]:
    """
    Return the Wazuh field names SIGMA_TO_WAZUH_FIELD_MAP suggests for
    `sigma_field` under the given (platform, decoder_name) context, most
    specific matches first (exact platform + a non-wildcard decoder pattern
    beats a "*"/"*" generic fallback entry). Empty list if no (platform,
    decoder) context is available or nothing in the map applies.
    """
    key = _find_sigma_map_key(sigma_field)
    if not key:
        return []

    contexts = SIGMA_TO_WAZUH_FIELD_MAP[key]
    scored: list[tuple[int, list[str]]] = []
    for (plat_pat, dec_pat), wazuh_fields in contexts.items():
        if not _platform_matches(plat_pat, platform) or not _decoder_matches(dec_pat, decoder_name):
            continue
        specificity = (0 if plat_pat == "*" else 1) + (0 if dec_pat == "*" else 1)
        scored.append((specificity, wazuh_fields))

    if not scored:
        return []

    scored.sort(key=lambda s: -s[0])
    seen = set()
    ordered: list[str] = []
    for _, fields in scored:
        for f in fields:
            if f not in seen:
                seen.add(f)
                ordered.append(f)
    return ordered


def fields_compatible(sigma_field: str, decoder_field: str,
                       platform: str | None = None, decoder_name: str | None = None) -> bool:
    """
    True if a Sigma field name and a decoder-extracted field name refer to the
    same underlying value. Checked in order of strictness:
      1. platform/decoder-aware semantic mapping table (SIGMA_TO_WAZUH_FIELD_MAP)
         — used first, and only, when a (platform, decoder_name) context is
         supplied, since it encodes real knowledge about what a specific
         decoder actually extracts (e.g. Sigma "CommandLine" legitimately
         maps to "audit.execve.a0".."a7" on Linux/auditd, a relationship no
         generic string heuristic could ever discover — and one that would be
         wrong to apply on Windows/sysmon).
      2. exact match after normalization
      3. shared alias group (curated, platform-agnostic semantic mapping)
      4. substring containment (weakest signal, last resort)
    Steps 2-4 are unchanged from before and still run as a fallback even when
    context is supplied, in case SIGMA_TO_WAZUH_FIELD_MAP doesn't (yet) cover
    that field/context combination.
    """
    sf, df = normalize_field(sigma_field), normalize_field(decoder_field)
    if not sf or not df:
        return False

    if platform or decoder_name:
        for candidate in get_wazuh_field_candidates(sigma_field, platform, decoder_name):
            if normalize_field(candidate) == df:
                return True

    if sf == df:
        return True
    group = _alias_group_for(sigma_field)
    if group and any(normalize_field(g) == df for g in group):
        return True
    if sf in df or df in sf:
        return True
    return False


def field_compatibility_score(sigma_fields: list[str], extracted_fields: list[str],
                               platform: str | None = None, decoder_name: str | None = None
                               ) -> tuple[int, list[str], list[str]]:
    """
    Compare a list of Sigma-required fields against a decoder's extracted
    fields. Returns (matched_count, matched_sigma_fields, missing_sigma_fields).

    A Sigma field counts as matched if it is compatible with ANY one of the
    decoder's extracted fields — this is already a full (not partial) match
    per Sigma field. For Linux/auditd + "CommandLine", the presence of any
    single "audit.execve.aN" (or the reconstructed "audit.execve.a0-a7") is
    therefore sufficient on its own to mark "CommandLine" as fully matched,
    since those args reconstruct into a full command line.

    `platform`/`decoder_name` are optional context that, when supplied, let
    fields_compatible() consult the semantic SIGMA_TO_WAZUH_FIELD_MAP before
    falling back to generic heuristics.
    """
    if not sigma_fields:
        return 0, [], []
    matched, missing = [], []
    for sf in sigma_fields:
        if any(fields_compatible(sf, ef, platform, decoder_name) for ef in extracted_fields):
            matched.append(sf)
        else:
            missing.append(sf)
    return len(matched), matched, missing


class ValidatorAgent:
    STATIC_FIELDS = ["url", "srcip", "dstip", "user", "id", "protocol", "action", "status"]

    def __init__(self, db):
        self.db = db
        self.reviews = []
        logger.info("ValidatorAgent initialized")

    def validate(self, xml_string: str, expected_platform: str, expected_decoder: str) -> tuple[bool, list[str]]:
        self.reviews = []
        logger.info(f"Starting validation (platform={expected_platform}, decoder={expected_decoder})")

        # Check 1: XML syntax
        valid, error = self._validate_xml_syntax(xml_string)
        if not valid:
            self.reviews.append(error)
        else:
            logger.info("XML syntax: PASS")

        # Check 2: if_sid
        if valid:
            valid_sid, error = self._validate_if_sid(xml_string, expected_platform)
            if not valid_sid:
                self.reviews.append(error)
                suggested = self._find_valid_parent(expected_platform)
                if suggested:
                    self.reviews.append(f"Suggested valid parent: {suggested}")
            else:
                logger.info("if_sid: PASS")

        # Check 3: Decoder fields (platform-aware semantic matching)
        valid_fields, error = self._validate_decoder_fields(xml_string, expected_decoder, expected_platform)
        if not valid_fields:
            self.reviews.append(error)
        else:
            logger.info("Decoder fields: PASS")

        is_valid = len(self.reviews) == 0
        return is_valid, self.reviews

    def _validate_xml_syntax(self, xml_string: str) -> tuple[bool, str | None]:
        try:
            ET.fromstring(xml_string)
            return True, None
        except ET.ParseError as e:
            return False, f"XML syntax error: {e}"

    def _validate_if_sid(self, xml_string: str, expected_platform: str) -> tuple[bool, str | None]:
        match = re.search(r'<if_sid>(\d+)</if_sid>', xml_string)
        if not match:
            return True, None

        parent_id = match.group(1)
        parent = self._get_rule_by_id(parent_id)
        if not parent:
            return False, f"Parent rule {parent_id} does not exist in the knowledge base"

        parent_platform = parent.metadata.get("platform", "unknown")
        if expected_platform != "unknown" and parent_platform != expected_platform:
            return False, f"Parent {parent_id} handles {parent_platform} events, but this rule is for {expected_platform}"

        parent_level = int(parent.metadata.get("rule_level", 0) or 0)
        has_children = parent.metadata.get("has_children", False)
        is_grouping = (parent_level <= 2) or has_children

        if not is_grouping:
            return False, f"Parent {parent_id} is not a valid grouping rule (level={parent_level})"

        return True, None

    def _validate_decoder_fields(self, xml_string: str, decoder_name: str,
                                  platform: str | None = None) -> tuple[bool, str | None]:
        decoder = self._get_decoder_by_name(decoder_name)
        if not decoder:
            return False, f"Decoder '{decoder_name}' not found in the knowledge base"

        extracted_fields = decoder.metadata.get("extracted_fields") or []
        if extracted_fields is None:
            extracted_fields = []

        field_matches = re.findall(r'<field name="([^"]+)"', xml_string)
        if not field_matches:
            return True, None

        errors = []
        for field in field_matches:
            if field in self.STATIC_FIELDS:
                errors.append(f"Static field '{field}' must use <{field}> tag")
                continue
            if field == "full_log":
                continue
            # Semantic match instead of strict string equality — consults the
            # platform/decoder-aware SIGMA_TO_WAZUH_FIELD_MAP first (e.g. a
            # decoder field "audit.execve.a3" satisfies rule field
            # "CommandLine" on linux/auditd), then falls back to the generic
            # normalize/alias/substring heuristics.
            if not any(fields_compatible(field, ef, platform, decoder_name) for ef in extracted_fields):
                errors.append(f"Field '{field}' not extracted by decoder '{decoder_name}'. Available: {extracted_fields}")

        if errors:
            return False, "; ".join(errors)
        return True, None

    def _get_rule_by_id(self, rule_id: str) -> Document | None:
        chroma_filter = build_chroma_filter({"type": "rule", "rule_id": rule_id})
        results = self.db.similarity_search("", k=1, filter=chroma_filter)
        if results:
            return results[0]
        if hasattr(self, '_in_memory_parents') and rule_id in self._in_memory_parents:
            return self._in_memory_parents[rule_id]
        return None

    def _get_decoder_by_name(self, decoder_name: str) -> Document | None:
        """
        Resolve a decoder by name for validation.

        Priority: the in-memory decoder registered by the retrieval pipeline
        (via add_in_memory_decoder) is checked FIRST and returned as-is if
        present. That object is the one the resolution pipeline already
        picked and aggregated (see retrieval.resolve_decoder /
        _build_aggregated_decoder) — re-querying the DB here instead would
        silently discard that work and risk pulling back an arbitrary,
        differently-fielded chunk sharing the same decoder_name (Wazuh
        frequently splits one logical decoder like "auditd-syscall" across
        many separate <decoder> XML blocks, each with a different single
        <order> field).

        Only if nothing was registered in-memory do we fall back to querying
        the DB directly — and even then, we aggregate across every chunk
        sharing that name rather than trusting a single k=1 result.
        """
        if hasattr(self, '_in_memory_decoders') and decoder_name in self._in_memory_decoders:
            return self._in_memory_decoders[decoder_name]

        chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": decoder_name})
        results = self.db.similarity_search("", k=100, filter=chroma_filter)
        if not results:
            return None
        if len(results) == 1:
            return results[0]

        # Multiple XML blocks share this decoder name — union their
        # extracted fields instead of trusting whichever single chunk came
        # back first.
        field_union: list[str] = []
        seen = set()
        for d in results:
            for f in (d.metadata.get("extracted_fields") or []):
                if f not in seen:
                    seen.add(f)
                    field_union.append(f)
        merged_meta = dict(results[0].metadata)
        merged_meta["extracted_fields"] = field_union
        merged_meta["decoder_variant_count"] = len(results)
        return Document(page_content=results[0].page_content, metadata=merged_meta)

    def _find_valid_parent(self, platform: str) -> str | None:
        chroma_filter = build_chroma_filter({"type": "rule", "platform": platform, "has_children": True})
        results = self.db.similarity_search("", k=3, filter=chroma_filter)
        if results:
            return results[0].metadata.get("rule_id")
        return None

    def is_new_rule_type(self, decoder_exists: bool, has_child_decoder: bool,
                          has_compatible_fields: bool, valid_parent_count: int,
                          category: str | None, retrieved_rules: list) -> tuple[bool, str]:
        """
        Decide whether Bootstrap Mode is needed.

        All decoder resolution — including the parent/child search — now
        happens in the caller (retrieval.resolve_decoder). This method
        receives three independent signals about that resolution:

          - decoder_exists:        a decoder document was matched via exact
                                    platform+service (or fallback similarity)
                                    lookup, REGARDLESS of whether it has
                                    extracted fields. A parent decoder like
                                    `auditd` with 0 fields still counts here.
          - has_child_decoder:      the matched decoder (or the logsource in
                                    general) has at least one child decoder
                                    in the knowledge base.
          - has_compatible_fields:  at least one Sigma-required field was
                                    matched (semantically) against the fields
                                    extracted by the matched decoder OR any of
                                    its children.

        Bootstrap Mode is reserved for the genuinely new-logsource case: no
        decoder was found at all, it has no children to fall back to, and no
        field anywhere is compatible. A decoder existing at all — even a
        fieldless parent — means this is an already-known logsource, not a
        new one; weak parent-rule or category-relevance signals just mean
        "few example rules exist yet", which is not the same thing.
        """
        reasons = []

        if not decoder_exists:
            reasons.append("no_decoder_match_for_platform_service")

        if valid_parent_count == 0:
            reasons.append("no_valid_parent")

        if category and category != "unknown":
            relevant = sum(
                1 for r in retrieved_rules
                if category.lower() in (r.metadata.get("category", "") or "").lower()
            )
            if relevant == 0 and len(retrieved_rules) > 0:
                reasons.append(f"no_relevant_rules_for_{category}")

        is_new = (not decoder_exists) and (not has_child_decoder) and (not has_compatible_fields)

        return is_new, (", ".join(reasons) if reasons else "existing")

    def validate_decoder(self, decoder_xml: str, sigma_fields: list, decoder_name: str,
                          platform: str | None = None) -> tuple[bool, list[str], dict]:
        self.reviews = []
        coverage = {"covered": [], "missing": [], "mapped": {}}

        valid, error = self._validate_xml_syntax(decoder_xml)
        if not valid:
            self.reviews.append(f"Decoder XML syntax error: {error}")
            return False, self.reviews, coverage

        root = ET.fromstring(decoder_xml)
        has_prematch = root.find("prematch") is not None or root.get("prematch") is not None
        has_program = root.find("program_name") is not None
        has_parent = root.get("parent") is not None
        if not has_prematch and not has_program and not has_parent:
            self.reviews.append("Decoder must have <prematch> or <program_name>")

        extracted_fields = []
        for order_elem in root.iter("order"):
            if order_elem.text:
                extracted_fields.extend([f.strip() for f in order_elem.text.split(",")])
        for regex_elem in root.iter("regex"):
            if regex_elem.text:
                extracted_fields.extend(re.findall(r"\?P<([^>]+)>", regex_elem.text))
        extracted_fields = list(set([f for f in extracted_fields if f]))

        matched_count, covered, missing = field_compatibility_score(
            sigma_fields, extracted_fields, platform, decoder_name
        )
        mapped = {}
        for sf in covered:
            for ef in extracted_fields:
                if fields_compatible(sf, ef, platform, decoder_name):
                    mapped[sf] = ef
                    break

        coverage = {"covered": covered, "missing": missing, "mapped": mapped, "extracted_fields": extracted_fields}
        if missing:
            self.reviews.append(f"Decoder missing fields: {missing}")

        return len(self.reviews) == 0, self.reviews, coverage

    def add_in_memory_parent(self, parent_doc: Document):
        if not hasattr(self, '_in_memory_parents'):
            self._in_memory_parents = {}
        parent_id = parent_doc.metadata.get("rule_id")
        if parent_id:
            self._in_memory_parents[parent_id] = parent_doc

    def add_in_memory_decoder(self, decoder_doc: Document):
        if not hasattr(self, '_in_memory_decoders'):
            self._in_memory_decoders = {}
        decoder_name = decoder_doc.metadata.get("decoder_name")
        if decoder_name:
            self._in_memory_decoders[decoder_name] = decoder_doc