"""
Sigma -> Wazuh Retrieval & Generation Pipeline
================================================
Converts Sigma rules to Wazuh XML using SigWaz, Filtered RAG, LLM, ValidatorAgent.

FIX (2026-07): Sigma logsource classification previously collapsed `product`,
`service`, and `category` into a single "platform"/"expected_decoder" pair by
letting category silently override product. This caused rules like

    logsource:
        product: linux
        service: auditd

to compute platform="unknown"/decoder="unknown" (since `service` was never
read), which incorrectly triggered Bootstrap Mode even though "linux" +
"auditd" is an extremely common, well-understood logsource.

The fix keeps product / service / category as three independent fields all
the way through the pipeline:
    - platform  -> used for rule retrieval / vector filtering
    - service   -> used for decoder lookup + decoder/parent generation
    - category  -> used for rule specialization / relevance checks

FIX (2026-07, round 2): decoder resolution itself was too shallow. Looking up
`decoder_name == expected_decoder` (e.g. "auditd") often finds the *parent*
decoder, whose entire job is log-family identification, not field extraction
— fields live on its children ("auditd-syscall", "auditd-execve", ...). The
old code read "decoder found, 0 extracted fields" as "useless decoder" and
forced Bootstrap Mode, even though the correct child decoder existed one
level down.

This version replaces decoder resolution with `resolve_decoder()`, a
multi-stage process:

    1. Exact decoder lookup (platform + service, metadata only)
    2. Validate the matched decoder's fields against what Sigma needs
    3. If fields are missing, search the decoder's children (via
       root/parent hierarchy metadata written by ingestion.py)
    4. Rank parent + children candidates by field compatibility (using
       semantic/alias matching, not strict string equality)
    5. Only as an absolute last resort, fall back to vector similarity —
       never as the first or only signal, since similarity alone can return
       a wrong decoder (e.g. "windows-security" for a linux/auditd rule)
       just because the XML looks similar.

Bootstrap Mode now fires only when nothing usable is found anywhere in that
process: no decoder, no child decoder, and no field-compatible candidate.

FIX (2026-07, round 3): field compatibility checks throughout this module
(decoder resolution, generated-decoder scoring) now pass (platform,
decoder_name) context into field_compatibility_score()/fields_compatible(),
so they consult validator.SIGMA_TO_WAZUH_FIELD_MAP — the curated semantic
mapping for cross-platform fields like Sigma "Image"/"CommandLine" landing on
very different Wazuh field names depending on which decoder produced them
(Windows sysmon vs. Linux auditd vs. ...). generate_decoder() also now feeds
that same mapping into the LLM prompt so generated <field name="..."> tags
use Wazuh-correct names instead of guessing.

FIX (2026-07, round 4): parent rule generation now runs whenever a decoder is
selected but no existing parent's <decoded_as> matches it (previously only
ran in Bootstrap Mode or when there were no parents at all).

FIX (2026-07, round 5): Sigma rules that reference BOTH a parent process
(ParentImage/ParentCommandLine) AND a child process (Image/CommandLine) were
being sent through the single-rule LLM path like any other rule. On Linux
auditd this is structurally wrong (see module docstring in
`classify_process_correlation` and the pipeline spec doc): auditd logs each
process execution as its own self-contained event with no embedded parent
metadata, so a rule needing "parent process X spawned child process Y" can
only be expressed as TWO correlated rules (a level-0 parent baseline +
a child rule using <if_matched_sid>), never as one rule with two
same-named <field> tags (which Wazuh ANDs, making it unsatisfiable).
`classify_process_correlation()` + `handle_parent_child_correlation()` add
this classification and the full split/discovery/dedup protocol.
"""

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document
from validator import (
    ValidatorAgent,
    fields_compatible,
    field_compatibility_score,
    get_wazuh_field_candidates,
)
from utils import build_chroma_filter

import subprocess
import tempfile
import os
import re
import sys
import yaml

load_dotenv()
from google import genai
from logger import setup_logger
from groq import Groq

logger = setup_logger("retrieval", level="INFO")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

EMBEDDING_MODEL = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"batch_size": 32}
)

DB = Chroma(
    persist_directory="db/wazuh-knowledge-base",
    embedding_function=EMBEDDING_MODEL,
    collection_metadata={"hnsw:space": "cosine"},
    collection_name="wazuh_knowledge_base"
)

MAX_ITERATIONS = 3


# =============================================================================
# Classification maps
# =============================================================================
# NOTE: these are intentionally kept as three SEPARATE maps (product, service,
# category) rather than one merged dict, because a service like "sysmon" and a
# category like "process_creation" answer completely different questions and
# must never be allowed to silently overwrite each other.

# product/OS -> platform. This is the primary, most reliable signal for
# "where did the log come from".
PRODUCT_PLATFORM_MAP = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "m365": "microsoft365",
    "office365": "microsoft365",
    "okta": "okta",
    "github": "github",
    "kubernetes": "kubernetes",
    "google_workspace": "google_workspace",
    "onelogin": "onelogin",
    "cisco": "network",
    "paloalto": "network",
    "fortinet": "network",
    "zeek": "network",
    "opencanary": "network",
    "modsecurity": "web",
}

# service -> platform. Used only as a fallback when `product` is missing,
# since a service usually strongly implies its host platform (sysmon implies
# windows, auditd implies linux, etc). Never used to overwrite an explicit
# `product`.
SERVICE_PLATFORM_MAP = {
    "sysmon": "windows",
    "security": "windows",
    "system": "windows",
    "application": "windows",
    "powershell": "windows",
    "powershell-classic": "windows",
    "wmi": "windows",
    "taskscheduler": "windows",
    "applocker": "windows",
    "dns-server": "windows",
    "driver-framework": "windows",
    "windefend": "windows",
    "bits-client": "windows",
    "auditd": "linux",
    "sshd": "linux",
    "ssh": "linux",
    "cron": "linux",
    "systemd": "linux",
    "clamav": "linux",
    "docker": "linux",
    "kubernetes-audit": "kubernetes",
    "modsecurity": "web",
    "apache": "web",
    "nginx": "web",
    "iis": "web",
    "cloudtrail": "aws",
    "guardduty": "aws",
    "vpcflow": "aws",
    "azuread": "azure",
    "azure.activitylogs": "azure",
    "azure.signinlogs": "azure",
    "gcp.audit": "gcp",
    "okta": "okta",
    "github-audit": "github",
}

# category -> platform. Weakest fallback signal, used only when neither
# product nor service is present.
CATEGORY_PLATFORM_MAP = {
    "webserver": "web",
    "firewall": "network",
    "proxy": "network",
    "dns": "network",
    "network_connection": "network",
    "antivirus": "endpoint",
}

# service -> decoder name. This is the primary signal for decoder lookup,
# since the decoder is what actually parses the raw log line and that is
# determined by *which logging subsystem* produced the event, not by which
# OS it runs on.
SERVICE_DECODER_MAP = {
    "auditd": "auditd",
    "sysmon": "windows-sysmon",
    "security": "windows-security",
    "system": "windows-system",
    "application": "windows-application",
    "powershell": "windows-powershell",
    "powershell-classic": "windows-powershell-classic",
    "wmi": "windows-wmi",
    "taskscheduler": "windows-taskscheduler",
    "applocker": "windows-applocker",
    "dns-server": "windows-dns-server",
    "sshd": "sshd",
    "ssh": "sshd",
    "cron": "cron",
    "systemd": "systemd",
    "clamav": "clamav",
    "docker": "docker",
    "kubernetes-audit": "kubernetes-audit",
    "apache": "apache-accesslog",
    "nginx": "nginx-accesslog",
    "iis": "iis-accesslog",
    "modsecurity": "modsecurity",
    "cloudtrail": "aws-cloudtrail",
    "guardduty": "aws-guardduty",
    "vpcflow": "aws-vpcflow",
    "azuread": "azure-ad",
    "azure.activitylogs": "azure-activitylogs",
    "azure.signinlogs": "azure-signinlogs",
    "gcp.audit": "gcp-audit",
    "okta": "okta",
    "github-audit": "github-audit",
}

# category -> decoder name. Fallback used only when `service` is absent
# (e.g. some Sigma rules only specify category: webserver with no service).
CATEGORY_DECODER_MAP = {
    "webserver": "web-accesslog",
    "firewall": "firewall-generic",
    "dns": "dns-generic",
    "proxy": "proxy-generic",
    "antivirus": "antivirus-generic",
    "process_creation": "auditd",
}


def _norm(value: str | None) -> str | None:
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def extract_sigma_fields(sigma: dict) -> list[str]:
    fields = set()
    detection = sigma.get("detection", {})
    def extract(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                field_name = key.split("|")[0]
                if field_name not in ["selection", "filter", "condition"]:
                    fields.add(field_name)
                extract(value)
        elif isinstance(obj, list):
            for item in obj:
                extract(item)
    extract(detection)
    return sorted(list(fields))


def classify_sigma_rule(yaml_content: str) -> dict:
    """
    Classify a Sigma rule's logsource, preserving product/service/category as
    independent dimensions (see module docstring for rationale).
    """
    sigma = yaml.safe_load(yaml_content)
    logsource = sigma.get("logsource", {}) or {}

    product = _norm(logsource.get("product"))
    service = _norm(logsource.get("service"))
    category = _norm(logsource.get("category"))

    # --- Platform resolution -------------------------------------------------
    # Priority: explicit product > service-implied platform > category-implied
    # platform. product is authoritative when present; it is NEVER overwritten
    # by category or service.
    platform = (
        PRODUCT_PLATFORM_MAP.get(product)
        or (SERVICE_PLATFORM_MAP.get(service) if service else None)
        or (CATEGORY_PLATFORM_MAP.get(category) if category else None)
        or product
        or "unknown"
    )

    # --- Decoder resolution ---------------------------------------------------
    # Priority: service (most specific -> tells us which parser we need) >
    # category (fallback when service absent).
    expected_decoder = (
        (SERVICE_DECODER_MAP.get(service) if service else None)
        or (CATEGORY_DECODER_MAP.get(category) if category else None)
    )

    # If nothing matched a known mapping, build a composite, *bootstrap-safe*
    # name that still preserves platform context instead of collapsing to a
    # bare "unknown" (previously: linux+auditd -> "linux_unknown").
    decoder_is_known = expected_decoder is not None
    if not expected_decoder:
        parts = [p for p in [platform if platform != "unknown" else None, service, category] if p]
        expected_decoder = "_".join(parts) if parts else "unknown"

    return {
        "platform": platform,
        "product": product,
        "service": service,
        "category": category,
        "expected_decoder": expected_decoder,
        "decoder_is_known_mapping": decoder_is_known,
        # kept for backwards compatibility with code that reads this key
        "logsource_category": category or "unknown",
        "sigma_fields": extract_sigma_fields(sigma)
    }


def extract_xml(output: str) -> str:
    match = re.search(r"(<group[\s\S]*?</group>)", output)
    if not match:
        raise Exception(f"No XML found in output")
    return match.group(1)


def convert_sigma_to_xml(yaml_content: str) -> str:
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(yaml_content)
        sigma_file = f.name
    try:
        SIGWAZ_PATH = os.path.join(os.path.dirname(__file__), "..", "sigwaz-cli", "sigwaz.py")
        result = subprocess.run(
            [sys.executable, SIGWAZ_PATH, "convert", sigma_file],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        if result.returncode != 0:
            raise Exception(result.stderr)
        output = result.stdout + "\n" + result.stderr
        skip = re.search(r"Skipped:\s*(.*)", output)
        if skip:
            raise Exception(f"SigWaz skipped: {skip.group(1)}")
        return extract_xml(output)
    finally:
        os.remove(sigma_file)


def retrieve_filtered(query: str, platform: str, db, k: int = 5) -> list[Document]:
    filter_dict = {"type": "rule"}
    if platform != "unknown":
        filter_dict["platform"] = platform
    chroma_filter = build_chroma_filter(filter_dict)
    results_with_scores = db.similarity_search_with_score(query, k=k, filter=chroma_filter)
    documents = []
    for doc, score in results_with_scores:
        doc.metadata["similarity"] = score
        documents.append(doc)
    return documents


# =============================================================================
# Decoder resolution
# =============================================================================

DECODER_VARIANT_FETCH_K = 100  # generous cap on how many same-named chunks we'll aggregate


def _aggregate_by_name(docs: list[Document]) -> dict[str, list[Document]]:
    """Group decoder documents by decoder_name."""
    groups: dict[str, list[Document]] = {}
    for d in docs:
        name = d.metadata.get("decoder_name")
        if not name:
            continue
        groups.setdefault(name, []).append(d)
    return groups


def _build_aggregated_decoder(name: str, docs: list[Document]) -> Document:
    """
    A single Wazuh decoder name (e.g. "auditd-syscall") is frequently split
    across MANY separate <decoder> XML blocks in the ruleset — one per
    regex/<order> variant (one block extracts audit.key, another
    audit.command, another audit.execve.a3, etc). Chroma stores each block as
    its own document, so "does auditd-syscall extract field X" can only be
    answered correctly by taking the UNION of extracted_fields across every
    chunk sharing that name — never by grabbing an arbitrary single chunk
    (which is what caused a real "audit.key" match to be reported as missing
    just because a k=1 lookup happened to return a different variant).
    """
    field_union: list[str] = []
    seen = set()
    for d in docs:
        for f in (d.metadata.get("extracted_fields") or []):
            if f not in seen:
                seen.add(f)
                field_union.append(f)
    merged_meta = dict(docs[0].metadata)
    merged_meta["extracted_fields"] = field_union
    merged_meta["decoder_variant_count"] = len(docs)
    combined_content = "\n<!-- variant -->\n".join(d.page_content for d in docs)
    return Document(page_content=combined_content, metadata=merged_meta)


def get_decoder_by_name_aggregated(name: str, db, k: int = DECODER_VARIANT_FETCH_K) -> Document | None:
    """Fetch every chunk sharing `name` and return one aggregated Document
    whose extracted_fields is the union across all of them."""
    if not name:
        return None
    chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": name})
    docs = db.similarity_search("", k=k, filter=chroma_filter)
    if not docs:
        return None
    return _build_aggregated_decoder(name, docs)


def get_child_decoders(parent_name: str, db, k: int = DECODER_VARIANT_FETCH_K) -> dict[str, Document]:
    """
    Find every decoder whose `parent_decoder` metadata equals `parent_name`,
    grouped and aggregated by decoder_name (see _build_aggregated_decoder).
    Pure metadata lookup — no embeddings involved — enabled by the
    root_decoder / is_child_decoder / decoder_depth fields written during
    ingestion. Returns {decoder_name: aggregated_document}.
    """
    if not parent_name:
        return {}
    chroma_filter = build_chroma_filter({"type": "decoder", "parent_decoder": parent_name})
    raw_docs = db.similarity_search("", k=k, filter=chroma_filter)
    groups = _aggregate_by_name(raw_docs)
    return {name: _build_aggregated_decoder(name, docs) for name, docs in groups.items()}


def _lookup_exact_decoder(platform: str, service: str | None, category: str | None,
                           expected_decoder: str, db) -> Document | None:
    """Stage 1: exact decoder lookup via metadata only (no embeddings),
    aggregated across every chunk sharing the matched name."""
    attempts = []
    if service:
        attempts.append({"type": "decoder", "platform": platform, "decoder_name": expected_decoder})
    if category:
        attempts.append({"type": "decoder", "platform": platform, "category": category})
    attempts.append({"type": "decoder", "decoder_name": expected_decoder})

    for filter_dict in attempts:
        chroma_filter = build_chroma_filter(filter_dict)
        results = db.similarity_search("", k=1, filter=chroma_filter)
        if results:
            name = results[0].metadata.get("decoder_name")
            return get_decoder_by_name_aggregated(name, db)
    return None


def _fallback_similarity_decoder(platform: str, expected_decoder: str, sigma_fields: list[str],
                                  db, log: dict) -> tuple[Document | None, dict]:
    """
    Stage 5 (last resort): vector similarity. Only reached when metadata
    filtering finds absolutely nothing. Never treated as authoritative on its
    own — a candidate is only accepted if it also passes field validation (or
    no fields are required at all).
    """
    logger.info("  No metadata match at all -> trying similarity fallback (last resort)")
    chroma_filter = build_chroma_filter({"type": "decoder", "platform": platform}) if platform != "unknown" else None
    results = db.similarity_search(expected_decoder, k=3, filter=chroma_filter)

    for doc in results:
        fields = doc.metadata.get("extracted_fields") or []
        decoder_name = doc.metadata.get("decoder_name")
        if not sigma_fields:
            log["selected_decoder"] = decoder_name
            log["selection_reason"] = "fallback_similarity_no_fields_required"
            log["has_compatible_fields"] = True
            return doc, log
        score, matched, missing = field_compatibility_score(sigma_fields, fields, platform, decoder_name)
        if score > 0:
            log["selected_decoder"] = decoder_name
            log["selection_reason"] = "fallback_similarity_field_match"
            log["has_compatible_fields"] = True
            return doc, log

    log["selection_reason"] = "no_decoder_found_anywhere"
    log["has_compatible_fields"] = False
    return None, log


def resolve_decoder(platform: str, service: str | None, category: str | None,
                     expected_decoder: str, sigma_fields: list[str], db) -> tuple[Document | None, dict]:
    """
    Multi-stage decoder resolution.

    Priority (per module docs): service > platform > parent/child
    relationship > field compatibility > semantic similarity (last resort).

        Sigma logsource
              |
              v
        Resolve expected service
              |
              v
        Search exact decoder (platform + service)
              |
        +-----+-----+
        |           |
     found       missing -> similarity fallback
        |
        v
    Validate extracted fields
        |
    +---+---------------------+
    |                         |
 satisfy                  missing
    |                         |
    |                         v
    |                  Check decoder children
    |                         |
    |                child found & compatible?
    |                  +------+------+
    |                  |             |
    |                 YES           NO
    |                  |             |
    |                  v             v
    |            Use child     No compatible fields
    |                                (candidate for Bootstrap)
    v
 Use existing (parent) decoder

    Returns (selected_document_or_None, resolution_log). `resolution_log`
    always contains enough detail to print the full decision trail (see
    main()'s "Decoder Resolution" log block).

    Field-compatibility checks at every stage pass (platform, decoder_name)
    context into field_compatibility_score(), so semantic, decoder-specific
    mappings (validator.SIGMA_TO_WAZUH_FIELD_MAP) are consulted before the
    generic string heuristics.
    """
    log = {
        "expected_service": service or category or expected_decoder,
        "initial_match": None,
        "initial_extracted_fields": [],
        "decoder_exists": False,
        "has_children": False,
        "children_checked": [],
        "selected_decoder": None,
        "selection_reason": None,
        "has_compatible_fields": False,
    }

    # ---- Stage 1: exact decoder lookup (metadata only) ---------------------
    initial_doc = _lookup_exact_decoder(platform, service, category, expected_decoder, db)

    if not initial_doc:
        doc, log = _fallback_similarity_decoder(platform, expected_decoder, sigma_fields, db, log)
        log["decoder_exists"] = doc is not None
        return doc, log

    log["decoder_exists"] = True
    log["initial_match"] = initial_doc.metadata.get("decoder_name")
    initial_fields = initial_doc.metadata.get("extracted_fields") or []
    log["initial_extracted_fields"] = initial_fields

    # ---- Stage 2: validate fields against the exact match ------------------
    if not sigma_fields:
        # Nothing to extract -> a structural/parent match is already enough.
        log["selected_decoder"] = log["initial_match"]
        log["selection_reason"] = "exact_match_no_fields_required"
        log["has_compatible_fields"] = True
        return initial_doc, log

    initial_score, initial_matched, initial_missing = field_compatibility_score(
        sigma_fields, initial_fields, platform, log["initial_match"]
    )
    if initial_score == len(sigma_fields):
        log["selected_decoder"] = log["initial_match"]
        log["selection_reason"] = "exact_match_fields_satisfied"
        log["has_compatible_fields"] = True
        return initial_doc, log

    # ---- Stage 3: fields missing/partial -> search children ---------------
    # get_child_decoders returns {decoder_name: aggregated_document} — a dict,
    # not a list — so it must be iterated with .items() to get (name, doc)
    # pairs. Iterating the dict directly yields only its string keys, which
    # is why `child.metadata` used to blow up with "'str' object has no
    # attribute 'metadata'".
    children = get_child_decoders(log["initial_match"], db)
    log["has_children"] = len(children) > 0

    # Parent counts as one of the candidates too, in case it's still the best
    # available option (e.g. partial field coverage beats a child with none).
    candidates = [(initial_doc, initial_score, initial_matched, initial_missing, log["initial_match"], False)]
    for child_name, child in children.items():
        child_fields = child.metadata.get("extracted_fields") or []
        score, matched, missing = field_compatibility_score(sigma_fields, child_fields, platform, child_name)
        log["children_checked"].append({
            "decoder_name": child_name,
            "fields": child_fields,
            "matched": matched,
            "missing": missing,
            "field_compatibility": "PASS" if score > 0 else "FAIL",
        })
        candidates.append((child, score, matched, missing, child_name, True))

    # ---- Stage 4: field compatibility ranking -------------------------------
    # Best score wins; children win ties over the parent since they're more
    # specific (that's what parent/child relationships are FOR).
    best_doc, best_score, best_matched, best_missing, best_name, best_is_child = max(
        candidates, key=lambda c: (c[1], c[5])
    )

    if best_score > 0:
        log["selected_decoder"] = best_name
        log["selection_reason"] = "child_decoder_field_match" if best_is_child else "exact_match_partial_fields"
        log["has_compatible_fields"] = True
        return best_doc, log

    # RETURN THE BEST DECODER even if field compatibility failed.
    # The LLM can handle field translation; this is infinitely better than
    # falling back to "syslog" which doesn't exist in the KB and breaks
    # validation.  best_score==0 just means "no semantic mapping yet", not
    # "decoder is useless".
    log["selected_decoder"] = best_name
    log["selection_reason"] = "child_decoder_field_match" if best_is_child else "exact_match_partial_fields"
    log["has_compatible_fields"] = best_score > 0
    return best_doc, log


def get_rule_by_id(rule_id: str, db) -> Document | None:
    chroma_filter = build_chroma_filter({"type": "rule", "rule_id": rule_id})
    results = db.similarity_search("", k=1, filter=chroma_filter)
    return results[0] if results else None


def add_parent_rules(documents: list[Document], db) -> tuple[dict, list[Document]]:
    parents = {}
    for doc in documents:
        match = re.search(r"<if_sid>(\d+)</if_sid>", doc.page_content)
        if not match:
            doc.metadata["parent_rule"] = None
            doc.metadata["parent_valid"] = False
            continue
        parent_id = match.group(1)
        doc.metadata["parent_rule"] = parent_id
        if parent_id in parents:
            continue
        parent = get_rule_by_id(parent_id, db)
        if parent:
            parents[parent_id] = parent
            level = int(parent.metadata.get("rule_level", 0) or 0)
            has_children = parent.metadata.get("has_children", False)
            doc.metadata["parent_valid"] = has_children or level <= 2
            doc.metadata["parent_level"] = level
        else:
            doc.metadata["parent_valid"] = False
    return parents, documents


def format_documents(documents, title: str) -> str:
    output = f"\n===== {title} =====\n"
    if not documents:
        return output + "None found\n"
    if isinstance(documents, dict):
        for key, doc in documents.items():
            output += f"\n--- {key} ---\nMetadata:\n{doc.metadata}\n\nContent:\n{doc.page_content}\n"
    else:
        for doc in documents:
            output += f"\nMetadata:\n{doc.metadata}\n\nContent:\n{doc.page_content}\n"
    return output


def _build_field_mapping_prompt_block(sigma_fields: list[str], platform: str, decoder_name: str) -> str:
    """
    Render the SIGMA_TO_WAZUH_FIELD_MAP guidance for this (platform,
    decoder_name) context as prompt text, so the decoder-generation LLM
    picks Wazuh-correct field names instead of guessing. `decoder_name` here
    is the best available context string (e.g. the service label like
    "auditd"/"sysmon"/"cloudtrail") — decoder-pattern matching in the map is
    substring-based (e.g. "*auditd*"), so this works even before a real
    decoder name has been assigned.
    """
    if not sigma_fields:
        return "  (no fields required)"
    lines = []
    for sf in sigma_fields:
        candidates = get_wazuh_field_candidates(sf, platform, decoder_name)
        if candidates:
            lines.append(f'  - Sigma "{sf}" -> use one of: {", ".join(candidates)}')
        else:
            lines.append(f'  - Sigma "{sf}" -> no known Wazuh mapping for this platform/decoder; choose a sensible field name')
    return "\n".join(lines)


def generate_decoder(sigma_info: dict, yaml_rule: str) -> tuple[str, list[str], dict]:
    platform = sigma_info["platform"]
    service = sigma_info.get("service")
    category = sigma_info.get("category") or sigma_info.get("logsource_category")
    sigma_fields = sigma_info.get("sigma_fields", [])

    # Prefer service for the decoder's identity — it's the actual log
    # provider. Only fall back to category when service is unavailable.
    decoder_label = service or category or "generic"

    logger.info(f"GENERATING decoder for platform={platform} service={service} "
                f"category={category} (needs fields: {sigma_fields})")

    # Semantic Sigma -> Wazuh field guidance for this (platform, decoder)
    # context, fed straight into the prompt so generated <field name="...">
    # tags land on names that will actually pass fields_compatible() /
    # field_compatibility_score() downstream instead of being guessed.
    field_mapping_text = _build_field_mapping_prompt_block(sigma_fields, platform, decoder_label)

    prompt = f"""You are an expert Wazuh decoder engineer. Generate a decoder XML.

SIGMA LOGSOURCE: product={platform}, service={service}, category={category}
FIELDS NEEDED: {sigma_fields}

SIGMA -> WAZUH FIELD NAME GUIDANCE FOR THIS PLATFORM/DECODER:
{field_mapping_text}

FULL SIGMA RULE:
{yaml_rule}

REQUIREMENTS:
1. Root element: <decoder name="{platform}_{decoder_label}">
2. MUST extract ALL fields: {sigma_fields}
3. Use the field name guidance above for <order>/named regex groups whenever a mapping is given for a field — don't invent an unrelated name when a known Wazuh field name is listed
4. Include <prematch> for log identification
5. Use <regex> with named groups OR <order> for field extraction
6. For Linux auditd/process_creation: use auditd format (type=EXECVE, a0=, a1=...) or syslog
7. For Linux auditd CommandLine specifically: "audit.execve.a0" through "audit.execve.a7" together reconstruct the full command line and are treated downstream as satisfying "CommandLine" completely
8. Valid Wazuh decoder XML only

Return ONLY the XML. No explanations."""

    interaction = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )
    output = interaction.choices[0].message.content.strip()

    decoder_xml = None
    match = re.search(r"(<decoder[\s\S]*?</decoder>)", output)
    if match:
        decoder_xml = match.group(1)
        logger.info(f"Decoder XML extracted: {len(decoder_xml)} chars")
    else:
        logger.error("FAILED to extract decoder XML")
        return None, [], {"covered": [], "missing": sigma_fields, "mapped": {}}

    extracted_fields = []
    order_matches = re.findall(r"<order>([^<]+)</order>", decoder_xml)
    for m in order_matches:
        extracted_fields.extend([f.strip() for f in m.split(",")])
    named_groups = re.findall(r"\?P<([^>]+)>", decoder_xml)
    extracted_fields.extend(named_groups)
    extracted_fields = list(set([f for f in extracted_fields if f]))

    matched_count, covered, missing = field_compatibility_score(
        sigma_fields, extracted_fields, platform, decoder_label
    )
    mapped = {}
    for sf in covered:
        for ef in extracted_fields:
            if fields_compatible(sf, ef, platform, decoder_label):
                mapped[sf] = ef
                break

    coverage = {"covered": covered, "missing": missing, "mapped": mapped, "extracted_fields": extracted_fields}
    return decoder_xml, extracted_fields, coverage


def generate_root_parent(decoder_name: str, platform: str) -> tuple[str, str]:
    parent_id = f"9{platform[:3].upper()}{hash(decoder_name) % 1000:03d}"
    logger.info(f"GENERATING root parent (id={parent_id}) for decoder '{decoder_name}'")
    parent_xml = f"""<group name="{platform},{decoder_name}">
  <rule id="{parent_id}" level="0">
    <decoded_as>{decoder_name}</decoded_as>
    <description>{platform} {decoder_name} events grouping</description>
  </rule>
</group>"""
    logger.info(f"Generated parent XML:\n{parent_xml}")
    return parent_xml, parent_id

def llm_call(results, parents, decoders, wazuh_rule, yaml_rule,
             reviews=None, is_bootstrap=False, generated_decoder=None,
             generated_parent=None, field_mapping=None, sigma_info=None) -> str:
    iteration = "1st" if reviews is None else f"retry ({len(reviews)} review(s))"

    rules_context = format_documents(results, "Retrieved Wazuh Rules")
    parents_context = format_documents(parents, "Parent Rules")
    decoders_context = format_documents(decoders, "Decoders")

    # ---- Build field mapping guidance for the LLM ----
    # Always use sigma_info + actual decoder to generate correct field names
    field_guidance = ""
    if sigma_info:
        platform = sigma_info.get("platform", "unknown")
        actual_decoder = list(decoders.keys())[0] if decoders else (
            sigma_info.get("service") or sigma_info.get("category") or "generic"
        )
        field_mapping_text = _build_field_mapping_prompt_block(
            sigma_info.get("sigma_fields", []), platform, actual_decoder
        )
        if field_mapping_text.strip() and field_mapping_text != "  (no fields required)":
            field_guidance = f"""
FIELD MAPPING FOR THIS DECODER — USE THESE EXACT WAZUH FIELD NAMES:
{field_mapping_text}

CRITICAL: Use the exact Wazuh field names above for <field name="..."> tags.
Do NOT use generic Windows names like "eventdata.image" when the mapping
specifies "audit.exe". Do NOT shorten "audit.exe" to "exe".
"""

    bootstrap_context = ""
    if is_bootstrap:
        bootstrap_context = f"""
========================
BOOTSTRAP MODE — NEW RULE TYPE

This Sigma rule maps to a NEW logsource type with no existing rules/decoders.

GENERATED DECODER (use <decoded_as> with this name):
{generated_decoder or "Using syslog fallback"}

GENERATED PARENT RULE (use this <if_sid>):
{generated_parent or "No parent generated"}

FIELD MAPPING (Sigma -> Wazuh decoder fields):
{field_mapping or "No mapping available"}

IMPORTANT:
- Use <decoded_as>{list(decoders.keys())[0] if decoders else 'syslog'}</decoded_as>
- Use <if_sid>{re.search(r'id="(\d+)"', generated_parent or '').group(1) if generated_parent and re.search(r'id="(\d+)"', generated_parent) else 'OMIT'}</if_sid>
- Use field names from the decoder's <order> or named regex groups
- Do NOT use <field name="full_log"> for log type context
"""

    reviews_section = ""
    if reviews:
        reviews_section = f"""
PREVIOUS VALIDATION ERRORS — FIX THESE:
{"\n".join(f"- {r}" for r in reviews)}
"""

    prompt = f"""You are an expert Wazuh detection engineer.

ORIGINAL SIGMA RULE:
{yaml_rule}

GENERATED WAZUH RULE:
{wazuh_rule}

{rules_context}

{parents_context}

{decoders_context}

{bootstrap_context}

{field_guidance}

{reviews_section}

CRITICAL CONSTRAINTS:
1. Wrap in <group name="..."> — never bare <rule>
2. Static fields use dedicated tags: <url>, <srcip>, <dstip>, <user>, <id>, <protocol>, <action>, <status>
3. <srcip>/<dstip> are for literal IPs only
4. No <field name="full_log"> for log type context
5. Single-line regex only
6. Same-field tags = AND logic — use | for OR
7. Only use fields the decoder extracts — see FIELD MAPPING above for exact names
8. type="pcre2" required for regex metacharacters
9. <if_sid> MUST exist in parents_context

Return ONLY the final Wazuh XML rule."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def main(yaml_rule: str | None = None):
    if yaml_rule is None:
        yaml_rule = """
title: Linux Webshell Indicators
id: 818f7b24-0fba-4c49-a073-8b755573b9c7
status: stable
description: Detects suspicious sub processes of web server processes
references:
    - https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
    - https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-10-15
modified: 2022-12-28
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    product: linux
    category: process_creation
detection:
    selection_general:
        ParentImage|endswith:
            - '/httpd'
            - '/lighttpd'
            - '/nginx'
            - '/apache2'
            - '/node'
            - '/caddy'
    selection_tomcat:
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'tomcat'
    selection_websphere:  # ? just guessing
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'websphere'
    sub_processes:
        Image|endswith:
            - '/whoami'
            - '/ifconfig'
            - '/ip'
            - '/bin/uname'
            - '/bin/cat'
            - '/bin/crontab'
            - '/hostname'
            - '/iptables'
            - '/netstat'
            - '/pwd'
            - '/route'
    condition: 1 of selection_* and sub_processes
falsepositives:
    - Web applications that invoke Linux command line tools
level: high

"""

    sigma_info = classify_sigma_rule(yaml_rule)
    platform = sigma_info["platform"]
    service = sigma_info.get("service")
    category = sigma_info.get("category")
    expected_decoder = sigma_info["expected_decoder"]
    sigma_fields = sigma_info.get("sigma_fields", [])

    logger.info(f"Classified logsource -> platform={platform}, service={service}, "
                f"category={category}, expected_decoder={expected_decoder}")

    wazuh_rule = convert_sigma_to_xml(yaml_rule)
    results = retrieve_filtered(wazuh_rule, platform, DB, k=5)
    parents, results = add_parent_rules(results, DB)

    # Step 5: DECODER RESOLUTION
    logger.info("[Step 5/7] Resolving decoder...")

    decoder_doc, resolution_log = resolve_decoder(platform, service, category, expected_decoder, sigma_fields, DB)

    decoders = {}
    generated_decoder_xml = None
    generated_parent_xml = None
    generated_parent_id = None
    field_mapping = {}
    is_bootstrap = False

    validator = ValidatorAgent(DB)

    valid_parent_count = sum(1 for d in results if d.metadata.get("parent_valid"))

    # ---- Detailed decoder resolution log (per spec) -------------------------
    logger.info("Decoder Resolution:")
    logger.info(f"  Expected service: {resolution_log['expected_service']}")
    logger.info(f"  Initial match: {resolution_log['initial_match'] or 'NONE'}")
    logger.info(f"  Extracted fields: {resolution_log['initial_extracted_fields']}")
    logger.info(f"  Decoder has children: {'YES' if resolution_log['has_children'] else 'NO'}")
    if resolution_log["children_checked"]:
        logger.info("  Searching children...")
        for child in resolution_log["children_checked"]:
            logger.info(f"    Candidate: {child['decoder_name']}")
            logger.info(f"    Fields: {child['fields']}")
            logger.info(f"    Field compatibility: {child['field_compatibility']}")
    logger.info(f"  Selected decoder: {resolution_log['selected_decoder'] or 'NONE'}")
    logger.info(f"  Selection reason: {resolution_log['selection_reason']}")

    if decoder_doc:
        expected_decoder = decoder_doc.metadata.get("decoder_name", expected_decoder)
        fields = decoder_doc.metadata.get('extracted_fields') or []
        logger.info(f"Using DB decoder: '{expected_decoder}' ({len(fields)} fields)")

        # CRITICAL: register the exact (already-aggregated) decoder that
        # resolve_decoder() picked into the validator's in-memory map. Without
        # this, ValidatorAgent._get_decoder_by_name() would independently
        # re-query the DB by name later during validate() and could come back
        # with a different, arbitrary chunk sharing the same decoder_name —
        # silently discarding the resolution work done above and reproducing
        # the exact "audit.key not extracted, available: audit.command" bug.
        validator.add_in_memory_decoder(decoder_doc)
        # Build field mapping for LLM prompt even in non-bootstrap mode
        # so it uses audit.exe instead of guessing "exe"
        field_mapping = {}
        for sf in sigma_fields:
            for ef in fields:
                if fields_compatible(sf, ef, platform, expected_decoder):
                    field_mapping[sf] = ef
                    break
        logger.info(f"Field mapping for LLM: {field_mapping}")

    # Bootstrap is driven by the full resolution outcome (decoder existence,
    # child existence, and field compatibility across the whole parent/child
    # tree) — not by a single collapsed "decoder found" flag. See
    # ValidatorAgent.is_new_rule_type docstring for the exact rule.
    is_new, reason = validator.is_new_rule_type(
        decoder_exists=resolution_log["decoder_exists"],
        has_child_decoder=resolution_log["has_children"],
        has_compatible_fields=resolution_log["has_compatible_fields"],
        valid_parent_count=valid_parent_count,
        category=category,
        retrieved_rules=results,
    )

    logger.info(f"  Bootstrap check: is_new={is_new}, reason={reason}")
    logger.info(f"  Bootstrap: {'TRUE' if is_new else 'FALSE'}")

    if is_new:
        logger.warning(">>> BOOTSTRAP MODE <<<")
        decoders = {}

        decoder_xml, extracted_fields, coverage = generate_decoder(sigma_info, yaml_rule)

        if decoder_xml:
            decoder_label = service or category or "generic"
            proposed_name = f"{platform}_{decoder_label}"
            is_dec_valid, dec_reviews, dec_coverage = validator.validate_decoder(
                decoder_xml, sigma_fields, proposed_name, platform
            )

            if is_dec_valid:
                logger.info("Decoder validation: PASSED")
                generated_decoder_xml = decoder_xml
                expected_decoder = proposed_name
                field_mapping = dec_coverage.get("mapped", {})
                is_bootstrap = True

                decoders[expected_decoder] = Document(
                    page_content=decoder_xml,
                    metadata={"type": "decoder", "decoder_name": expected_decoder,
                              "platform": platform, "service": service,
                              "extracted_fields": extracted_fields}
                )
                validator.add_in_memory_decoder(decoders[expected_decoder])
            else:
                logger.warning(f"Decoder validation failed: {dec_reviews}")
                expected_decoder = "syslog"
                is_bootstrap = True
        else:
            expected_decoder = "syslog"
            is_bootstrap = True
    elif not decoder_doc:
        # Resolution returned None but may still have a decoder name from
        # the log (shouldn't happen after resolve_decoder fix, but guard).
        fallback_name = resolution_log.get("selected_decoder")
        if fallback_name:
            expected_decoder = fallback_name
            decoder_doc = get_decoder_by_name_aggregated(expected_decoder, DB)
            if decoder_doc:
                decoders[expected_decoder] = decoder_doc
                fields = decoder_doc.metadata.get('extracted_fields') or []
                logger.info(f"Using DB decoder (re-fetched): '{expected_decoder}' ({len(fields)} fields)")
                validator.add_in_memory_decoder(decoder_doc)
            else:
                logger.warning(f"Could not re-fetch decoder '{fallback_name}', using syslog fallback")
                expected_decoder = "syslog"
        else:
            logger.warning("No decoder selected, using syslog fallback")
            expected_decoder = "syslog"

    # ---- FIX (2026-07, round 4): Generate parent when decoder selected but no matching parent exists ----
    # Previously this only ran when is_bootstrap or not parents, but parents
    # may exist while being wrong (e.g., syslog parents instead of auditd).
    has_decoder_parent = False
    if expected_decoder and expected_decoder != "syslog":
        has_decoder_parent = any(
            p.metadata.get("decoded_as") == expected_decoder
            for p in parents.values()
        )

    if is_bootstrap or not parents or (decoder_doc and not has_decoder_parent):
        parent_xml, parent_id = generate_root_parent(expected_decoder, platform)
        generated_parent_xml = parent_xml
        generated_parent_id = parent_id

        parent_doc = Document(
            page_content=parent_xml,
            metadata={"rule_id": parent_id, "platform": platform,
                      "rule_level": 0, "has_children": True}
        )
        parents[parent_id] = parent_doc
        validator.add_in_memory_parent(parent_doc)

    # PRINT EVERYTHING
    logger.info("=" * 60)
    logger.info("DECODER & PARENT RESOLUTION")
    logger.info("=" * 60)
    logger.info(f"Platform:         {platform}")
    logger.info(f"Service:          {service}")
    logger.info(f"Category:         {category}")
    logger.info(f"Decoder name:     {expected_decoder}")
    logger.info(f"Decoder source:   {'GENERATED (new)' if generated_decoder_xml else 'DB/INFERRED'}")
    if generated_decoder_xml:
        logger.info(f"Decoder XML:\n{generated_decoder_xml}")
    logger.info(f"Parent rule ID:   {generated_parent_id or 'NONE'}")
    if generated_parent_xml:
        logger.info(f"Parent XML:\n{generated_parent_xml}")
    logger.info(f"Field mapping:    {field_mapping}")
    logger.info(f"Bootstrap mode:   {is_bootstrap}")
    logger.info("=" * 60)

    reviews = None
    final_rule = None
    xml_rule = None

    for iteration in range(MAX_ITERATIONS):
        logger.info(f"--- Attempt {iteration + 1}/{MAX_ITERATIONS} ---")

        generated = llm_call(
            results, parents, decoders, wazuh_rule, yaml_rule, reviews,
            is_bootstrap=is_bootstrap,
            generated_decoder=generated_decoder_xml,
            generated_parent=generated_parent_xml,
            field_mapping=field_mapping,
            sigma_info=sigma_info
        )

        try:
            xml_rule = extract_xml(generated)
            logger.info(f"XML extracted: {len(xml_rule)} chars")
            if_sid_match = re.search(r'<if_sid>(\d+)</if_sid>', xml_rule)
            logger.info(f"  Rule if_sid: {if_sid_match.group(1) if if_sid_match else 'NONE'}")
        except Exception as e:
            logger.error(f"XML extraction failed: {e}")
            reviews = [f"Invalid XML: {e}"]
            continue

        is_valid, reviews = validator.validate(xml_rule, platform, expected_decoder)
        if is_valid:
            logger.info("VALIDATION PASSED")
            final_rule = xml_rule
            break
        else:
            logger.warning(f"VALIDATION FAILED: {len(reviews)} error(s)")
            for i, r in enumerate(reviews, 1):
                logger.warning(f"  {i}. {r[:150]}")

    result = final_rule or xml_rule

    logger.info("=" * 60)
    logger.info("FINAL OUTPUT SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Decoder:          {expected_decoder}")
    logger.info(f"Decoder source:   {'GENERATED' if generated_decoder_xml else 'EXISTING'}")
    logger.info(f"Parent ID:        {generated_parent_id or 'NONE'}")
    logger.info(f"Parent source:    {'GENERATED' if generated_parent_xml else 'EXISTING'}")
    if_sid = re.search(r'<if_sid>(\d+)</if_sid>', result) if result else None
    logger.info(f"Rule if_sid:      {if_sid.group(1) if if_sid else 'NONE'}")
    uses_fields = bool(result) and '<field name=' in result and 'full_log' not in result
    logger.info(f"Rule uses fields: {uses_fields}")
    logger.info(f"Validation:       {'PASSED' if final_rule else 'BEST EFFORT'}")
    logger.info("=" * 60)
    logger.info("RULE XML:")
    logger.info(result)

    return {
        "rule": result,
        "decoder_xml": generated_decoder_xml,
        "parent_xml": generated_parent_xml,
        "decoder_name": expected_decoder,
        "parent_id": generated_parent_id,
        "is_valid": final_rule is not None,
        "is_bootstrap": is_bootstrap
    }

if __name__ == "__main__":
    main()