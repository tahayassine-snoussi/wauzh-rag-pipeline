"""
Pipeline core: classification, retrieval, decoder resolution, parent-rule discovery,
and Category-C (parent/child) correlation handling.
"""
import os
import re
import subprocess
import sys
import tempfile
import yaml

from langchain_core.documents import Document

from utils import (
    DB, DECODER_VARIANT_FETCH_K, MAX_ITERATIONS,
    PRODUCT_PLATFORM_MAP, SERVICE_PLATFORM_MAP, CATEGORY_PLATFORM_MAP,
    SERVICE_DECODER_MAP, CATEGORY_DECODER_MAP,
    _norm, build_chroma_filter, retry_on_error, format_documents,
    XMLExtractionError, PipelineError,
    GROQ_CLIENT, LLM_CONFIG,
    extract_sigma_fields,
)
from validator import (
    ValidatorAgent,
    fields_compatible,
    field_compatibility_score,
    get_wazuh_field_candidates,
    normalize_field,
)

from logger import setup_logger
logger = setup_logger("pipeline", level="INFO")


# =============================================================================
# Classification
# =============================================================================

def classify_sigma_rule(yaml_content: str) -> dict:
    sigma = yaml.safe_load(yaml_content)
    logsource = sigma.get("logsource", {}) or {}

    product = _norm(logsource.get("product"))
    service = _norm(logsource.get("service"))
    category = _norm(logsource.get("category"))

    platform = (
        PRODUCT_PLATFORM_MAP.get(product)
        or (SERVICE_PLATFORM_MAP.get(service) if service else None)
        or (CATEGORY_PLATFORM_MAP.get(category) if category else None)
        or product
        or "unknown"
    )

    expected_decoder = (
        (SERVICE_DECODER_MAP.get(service) if service else None)
        or (CATEGORY_DECODER_MAP.get(category) if category else None)
    )

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
        "logsource_category": category or "unknown",
        "sigma_fields": extract_sigma_fields(sigma)
    }


def classify_process_correlation(sigma: dict) -> str:
    """
    Classify a Sigma rule into one of three categories:
      A = Child-Only, B = Parent-Only, C = Parent-Child Correlation.
    """
    detection = sigma.get("detection", {})
    has_parent = False
    has_child = False

    def _scan(obj):
        nonlocal has_parent, has_child
        if isinstance(obj, dict):
            for key in obj.keys():
                base = key.split("|")[0]
                if base in ("ParentImage", "ParentCommandLine"):
                    has_parent = True
                elif base in ("Image", "CommandLine"):
                    has_child = True
                _scan(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                _scan(item)

    _scan(detection)

    if has_parent and has_child:
        return "C"
    elif has_parent:
        return "B"
    else:
        return "A"


# =============================================================================
# Parent Rule Discovery & Helpers
# =============================================================================

def _patterns_overlap(sigma_values: list[str], existing_pattern: str) -> bool:
    existing_lower = existing_pattern.lower()
    for val in sigma_values:
        val_lower = val.lower().strip("/")
        if val_lower in existing_lower:
            return True
        for word in re.findall(r'[a-z0-9]+', existing_lower):
            if word == val_lower or word in val_lower:
                return True
    return False


def find_parent_rule(platform: str, parent_signature: dict, db, k: int = 10, decoder_name: str | None = None) -> Document | None:
    base_sid = "80700"
    filter_dict = {"type": "rule", "platform": platform, "rule_level": {"$lte": 2}}
    chroma_filter = build_chroma_filter(filter_dict)
    results = db.similarity_search("", k=k, filter=chroma_filter)

    logger.info(f"[Category C] Searching DB for parent baseline with filter: {filter_dict}")

    best_score = 0
    best_doc = None

    for doc in results:
        meta = doc.metadata
        rule_id = meta.get("rule_id", "unknown")
        content = doc.page_content
        level = int(meta.get("rule_level", 99) or 99)
        if level > 2:
            continue

        if_sid_match = re.search(r'<if_sid>(\d+)</if_sid>', content)
        decoded_as_match = re.search(r'<decoded_as>([^<]+)</decoded_as>', content)

        has_valid_base = (if_sid_match and if_sid_match.group(1) == base_sid)
        has_matching_decoder = False
        if decoded_as_match and decoder_name:
            has_matching_decoder = decoded_as_match.group(1).strip() == decoder_name
        elif decoded_as_match:
            has_matching_decoder = True

        if not has_valid_base and not has_matching_decoder:
            logger.info(f"[Category C] Candidate {rule_id}: wrong base or decoder, SKIP")
            continue

        field_matches = re.findall(r'<field name="([^"]+)"[^>]*>([^<]+)</field>', content)
        if not field_matches:
            logger.info(f"[Category C] Candidate {rule_id}: no field tags, SKIP")
            continue

        score = 0
        matched_patterns = []
        for field_name, pattern in field_matches:
            for sig_key, sig_values in parent_signature.items():
                sig_base = sig_key.split("|")[0]
                wazuh_candidates = get_wazuh_field_candidates(sig_base, platform, "auditd")
                if any(normalize_field(c) == normalize_field(field_name) for c in wazuh_candidates):
                    if isinstance(sig_values, list) and _token_basename_overlap(sig_values, pattern):
                        score += 1
                        matched_patterns.append(pattern)

        logger.info(f"[Category C] Candidate {rule_id}: overlap_score={score}, patterns={matched_patterns}")

        if score > best_score:
            best_score = score
            best_doc = doc

    if best_doc is None:
        logger.info(f"[Category C] No existing parent baseline found for signature: {parent_signature}")

    return best_doc


def _find_generic_process_parent(platform: str, db, k: int = 10) -> Document | None:
    filter_dict = {"type": "rule", "platform": platform, "rule_level": 0}
    chroma_filter = build_chroma_filter(filter_dict)
    results = db.similarity_search("", k=k, filter=chroma_filter)

    for doc in results:
        content = doc.page_content
        if_sid_match = re.search(r'<if_sid>(\d+)</if_sid>', content)
        if not if_sid_match or if_sid_match.group(1) != "80700":
            continue

        exe_match = re.search(r'<field name="audit\.exe"[^>]*>([^<]+)</field>', content)
        if exe_match:
            pattern = exe_match.group(1)
            if re.search(r'/bash\$|/sh\$|/bash\||/sh\||\bbash\b|\bsh\b', pattern):
                return doc
    return None


def _extract_parent_signatures(sigma: dict) -> dict:
    detection = sigma.get("detection", {})
    unified: dict[str, list] = {}

    def _collect(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                base = k.split("|")[0]
                if base in ("ParentImage", "ParentCommandLine"):
                    vals = v if isinstance(v, list) else [v]
                    if k in unified:
                        existing = set(unified[k])
                        existing.update(vals)
                        unified[k] = list(existing)
                    else:
                        unified[k] = list(vals)
                else:
                    _collect(v)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item)

    for key, value in detection.items():
        if key == "condition":
            continue
        _collect(value)

    return unified


def _extract_child_signatures(sigma: dict) -> dict:
    detection = sigma.get("detection", {})
    child_sig = {}

    for key, value in detection.items():
        if key in ("condition",):
            continue

        def _collect(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    base = k.split("|")[0]
                    if base in ("Image", "CommandLine"):
                        child_sig[base] = v if isinstance(v, list) else [v]
                    else:
                        _collect(v)
            elif isinstance(obj, list):
                for item in obj:
                    _collect(item)
        _collect(value)

    return child_sig


def _generate_rule_id(platform: str, idx: int = 0) -> str:
    return f"9{platform[:3].upper()}{idx + 1:03d}"


# =============================================================================
# Category C Correlation Handler
# =============================================================================

def _build_category_c_prompt(
    yaml_rule: str,
    sigma_info: dict,
    field_mapping_text: str,
    parent_candidates: list[Document],
    existing_parent_xmls: list[str],
    parent_id: str,
    child_id: str,
    parent_signature: dict,
    base_if_sid: str
) -> str:
    platform = sigma_info["platform"]
    level = sigma_info.get("level", "high")

    candidate_text = ""
    if parent_candidates:
        candidate_text = "\n\nEXISTING PARENT CANDIDATES:\n"
        for i, doc in enumerate(parent_candidates, 1):
            candidate_text += f"\n--- Candidate {i} (ID: {doc.metadata.get('rule_id', 'unknown')}) ---\n{doc.page_content}\n"

    if existing_parent_xmls:
        candidate_text += "\n\nGENERATED PARENT RULES TO REUSE:\n"
        for xml in existing_parent_xmls:
            candidate_text += f"\n{xml}\n"

    sig_lines = []
    for sig_key, sig_values in parent_signature.items():
        base_field = sig_key.split("|")[0]
        modifier = "|".join(sig_key.split("|")[1:]) if "|" in sig_key else "equals"
        val_str = repr(sig_values)
        sig_lines.append(f"- {base_field} ({modifier}): {val_str}")

    structured_signature = "\n".join(sig_lines)

    prompt = f"""You are an expert Wazuh detection engineer. This Sigma rule requires PARENT-CHILD CORRELATION.

ORIGINAL SIGMA RULE:
{yaml_rule}

PLATFORM: {platform}
FIELDS NEEDED: {sigma_info.get('sigma_fields', [])}

SIGMA -> WAZUH FIELD NAME GUIDANCE FOR THIS PLATFORM/DECODER:
{field_mapping_text}
{candidate_text}

PARENT SIGNATURE TO MATCH:
{structured_signature}

[CRITICAL CONSTRAINTS — PARENT-CHILD CORRELATION]
1. Linux auditd logs parent and child executions as SEPARATE events.
   There is NO "ParentImage" field inside a child event.
2. This Sigma rule references BOTH parent (ParentImage/ParentCommandLine)
   AND child (Image/CommandLine) fields. You MUST generate TWO rules:

   PARENT RULE (level=0 baseline):
   - Uses <if_sid>{base_if_sid}</if_sid> pointing to the base process creation rule.
   - Contains <field name="audit.exe"> matching the PARENT process image.
   - Contains <field name="audit.command"> matching PARENT command line (if present).
   - This is a baseline rule that fires on every parent process execution.

   CHILD RULE (level={level} detection):
   - Uses <if_matched_sid> pointing to the PARENT rule ID.
   - Contains ONLY child fields: <field name="audit.exe"> for child Image.
   - Contains <field name="audit.command"> for child CommandLine (if present).
   - NEVER include parent patterns here.

3. NEVER put two <field name="audit.exe"> tags in the same rule to match
   different processes. Wazuh ANDs same-named fields, making the rule impossible.
4. The parent rule ID must be referenced correctly in <if_matched_sid>.
5. Use type="pcre2" for all regex fields.
6. If multiple parent selectors exist (e.g. web servers AND tomcat), create
   ONE parent rule that ORs all parent image patterns together, and ONE child
   rule that uses <if_matched_sid> pointing to that single parent.

[NEGATIVE CONSTRAINTS]
- Parent rule ID MUST be {parent_id}. Child rule ID MUST be {child_id}.
- DO NOT add any fields not listed in the parent signature.
- Do NOT invent fields like audit.ppid, audit.uid, or audit.auid.
- For contains|all conditions, use multiple <field name="audit.command"> tags (Wazuh ANDs same-named fields).
- For endswith with a list of values, use ONE <field name="audit.exe"> tag with a PCRE2 alternation: (?i)(?:value1|value2)$.
- The child rule MUST include <frequency>1</frequency> and <timeframe>60</timeframe> inside the <rule> tag.

Return your output in this exact format:

=== PARENT RULE ===
<group name="...">
  <rule id="{parent_id}" level="0">
    ...
  </rule>
</group>

=== CHILD RULE ===
<group name="...">
  <rule id="{child_id}" level="...">
    <if_matched_sid>{parent_id}</if_matched_sid>
    ...
  </rule>
</group>

Return ONLY the two XML blocks. No explanations.
"""
    return prompt


def _extract_tagged_xml(output: str, tag: str) -> str | None:
    pattern = rf"=== {tag} ===\s*(<group[\s\S]*?</group>)"
    match = re.search(pattern, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    parts = re.split(rf"=== {tag} ===", output, flags=re.IGNORECASE)
    if len(parts) > 1:
        group_match = re.search(r"(<group[\s\S]*?</group>)", parts[1])
        if group_match:
            return group_match.group(1).strip()
    return None


def _extract_rule_id(xml_string: str) -> str | None:
    match = re.search(r'<rule\s+id="(\d+)"', xml_string)
    if match:
        return match.group(1)
    return None


def _canonical_parent_fingerprint(xml: str) -> tuple | None:
    if_sid_match = re.search(r'<if_sid>(\d+)</if_sid>', xml)
    if not if_sid_match:
        return None
    if_sid = if_sid_match.group(1)

    fields = []
    for field_name, pattern in re.findall(r'<field name="([^"]+)"[^>]*>([^<]+)</field>', xml):
        norm_pat = normalize_field(pattern)
        fields.append((field_name, norm_pat))
    fields.sort()

    return (if_sid, tuple(fields))


def _is_duplicate_parent(new_xml: str, existing_xmls: list[str]) -> tuple[bool, str | None]:
    new_fp = _canonical_parent_fingerprint(new_xml)
    if not new_fp:
        return False, None

    for existing in existing_xmls:
        ex_fp = _canonical_parent_fingerprint(existing)
        if ex_fp and ex_fp == new_fp:
            ex_id = _extract_rule_id(existing)
            return True, ex_id
    return False, None

@retry_on_error(max_retries=3, backoff=2)
def _llm_generate_category_c(prompt: str) -> str:
    interaction = GROQ_CLIENT.chat.completions.create(
        model=LLM_CONFIG.model,
        messages=[{"role": "user", "content": prompt}],
        temperature=LLM_CONFIG.temperature,
        max_tokens=LLM_CONFIG.max_tokens,
    )
    return interaction.choices[0].message.content.strip()


def handle_parent_child_correlation(
    sigma: dict,
    sigma_info: dict,
    yaml_rule: str,
    db
) -> dict:
    platform = sigma_info["platform"]
    service = sigma_info.get("service")
    category = sigma_info.get("category")
    expected_decoder = sigma_info["expected_decoder"]
    sigma_fields = sigma_info.get("sigma_fields", [])

    logger.info("[Category C] Handling parent-child correlation...")

    decoder_doc, resolution_log = resolve_decoder(
        platform, service, category, expected_decoder, sigma_fields, db
    )

    actual_decoder = resolution_log.get("selected_decoder") or expected_decoder
    if decoder_doc:
        actual_decoder = decoder_doc.metadata.get("decoder_name", actual_decoder)

    field_mapping_text = _build_field_mapping_prompt_block(
        sigma_fields, platform, actual_decoder
    )

    parent_signature = _extract_parent_signatures(sigma)
    logger.info(f"[Category C] Extracted unified parent signature: {parent_signature}")

    parent_candidates = []
    candidate = find_parent_rule(platform, parent_signature, db, decoder_name=actual_decoder)
    if candidate:
        parent_candidates.append(candidate)

    base_if_sid = "80700"
    generic_parent = _find_generic_process_parent(platform, db)
    if generic_parent:
        generic_id = generic_parent.metadata.get("rule_id")
        logger.info(f"[Category C] Using generic process parent {generic_id} as base for new specific parent.")
        base_if_sid = generic_id
    else:
        logger.info("[Category C] No generic process parent found, falling back to base rule 80700.")

    parent_id = _generate_rule_id(platform, 0)
    child_id = _generate_rule_id(platform, 1)
    logger.info(f"[Category C] Assigned IDs: parent={parent_id}, child={child_id}")

    existing_parent_xmls = []

    prompt = _build_category_c_prompt(
        yaml_rule, sigma_info, field_mapping_text, parent_candidates,
        existing_parent_xmls, parent_id, child_id, parent_signature, base_if_sid
    )

    logger.info("[Category C] Prompt built, calling LLM...")
    output = _llm_generate_category_c(prompt)
    logger.info(f"[Category C] Raw LLM output length: {len(output)}")

    # Enforce deterministic IDs and base if_sid
    output = re.sub(r'(<rule\s+id=")\d+(")', rf'\g<1>{parent_id}\g<2>', output, count=1)
    output = re.sub(r'(<rule\s+id=")\d+(")', rf'\g<1>{child_id}\g<2>', output)
    output = re.sub(r'(<if_matched_sid>)\d+(</if_matched_sid>)', rf'\g<1>{parent_id}\g<2>', output)
    output = re.sub(r'(<if_sid>)\d+(</if_sid>)', rf'\g<1>{base_if_sid}\g<2>', output)

    parent_xml = _extract_tagged_xml(output, "PARENT RULE")
    child_xml = _extract_tagged_xml(output, "CHILD RULE")

    logger.info(f"[Category C] Extracted parent XML: {parent_xml is not None}, child XML: {child_xml is not None}")

    if not parent_xml or not child_xml:
        raise XMLExtractionError(
            f"Category C LLM output did not contain both PARENT and CHILD rules. Output:\n{output[:500]}"
        )

    all_existing_xmls = [p.page_content for p in parent_candidates] + existing_parent_xmls
    is_dup, existing_id = _is_duplicate_parent(parent_xml, all_existing_xmls)

    if is_dup:
        logger.info(f"[Category C] Parent discovery result: deduplicated_to_id={existing_id}")
        parent_xml = None
        parent_id = existing_id
    else:
        logger.info(f"[Category C] Parent discovery result: generated_new (base_if_sid={base_if_sid})")

    validator = ValidatorAgent(db)

    if parent_xml:
        validator.add_in_memory_parent(Document(
            page_content=parent_xml,
            metadata={"rule_id": parent_id, "platform": platform, "rule_level": 0, "has_children": True}
        ))
        existing_parent_xmls.append(parent_xml)

    is_valid_parent = True
    parent_reviews = []
    if parent_xml:
        is_valid_parent, parent_reviews = validator.validate(parent_xml, platform, actual_decoder)
        collision_ok, collision_msg = validator._validate_field_collisions(parent_xml)
        if not collision_ok:
            is_valid_parent = False
            parent_reviews.append(collision_msg)

    is_valid_child, child_reviews = validator.validate(child_xml, platform, actual_decoder)
    collision_ok, collision_msg = validator._validate_field_collisions(child_xml)
    if not collision_ok:
        is_valid_child = False
        child_reviews.append(collision_msg)

    purity_ok, purity_msg = validator._validate_child_rule_purity(child_xml)
    if not purity_ok:
        is_valid_child = False
        child_reviews.append(purity_msg)

    matched_ok, matched_msg = validator._validate_if_matched_sid(child_xml)
    if not matched_ok:
        is_valid_child = False
        child_reviews.append(matched_msg)

    all_reviews = parent_reviews + child_reviews
    is_valid = is_valid_parent and is_valid_child and len(all_reviews) == 0

    fidelity_ok, fidelity_msg = validator._validate_category_c_fidelity(sigma, [parent_xml, child_xml])
    if not fidelity_ok:
        is_valid = False
        all_reviews.append(fidelity_msg)

    rules_output = []
    if parent_xml:
        rules_output.append({
            "rule_id": parent_id,
            "xml": parent_xml,
            "type": "parent_baseline"
        })
    else:
        rules_output.append({
            "rule_id": parent_id,
            "xml": next((p.page_content for p in parent_candidates if p.metadata.get("rule_id") == parent_id), ""),
            "type": "parent_baseline"
        })

    rules_output.append({
        "rule_id": child_id,
        "xml": child_xml,
        "type": "detection",
        "if_matched_sid": parent_id
    })

    logger.info("=" * 60)
    logger.info("CATEGORY C OUTPUT SUMMARY")
    logger.info("=" * 60)
    for r in rules_output:
        logger.info(f"Rule {r['rule_id']} ({r['type']}):\n{r['xml'][:200]}...")
    logger.info(f"Validation: {'PASSED' if is_valid else 'FAILED'}")
    if all_reviews:
        for rev in all_reviews:
            logger.warning(f"  - {rev}")
    logger.info("=" * 60)

    return {
        "rules": rules_output,
        "decoder_name": actual_decoder,
        "is_bootstrap": False,
        "is_valid": is_valid,
        "reviews": all_reviews
    }

# =============================================================================
# Existing retrieval / conversion functions
# =============================================================================

def extract_xml(output: str) -> str:
    match = re.search(r"(<group[\s\S]*?</group>)", output)
    if not match:
        raise XMLExtractionError(f"No XML found in output")
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
            raise PipelineError(result.stderr)
        output = result.stdout + "\n" + result.stderr
        skip = re.search(r"Skipped:\s*(.*)", output)
        if skip:
            raise PipelineError(f"SigWaz skipped: {skip.group(1)}")
        return extract_xml(output)
    finally:
        os.remove(sigma_file)


def _token_basename_overlap(sigma_values: list[str], existing_pattern: str) -> bool:
    sigma_tokens = set()
    for val in sigma_values:
        basename = val.strip("/").split("/")[-1].lower()
        if basename:
            sigma_tokens.add(basename)

    existing_tokens = set()
    for part in existing_pattern.split("|"):
        cleaned = re.sub(r'[\\^$.*+?()\[\]{}]', '', part).strip().lower()
        if cleaned:
            basename = cleaned.split("/")[-1]
            existing_tokens.add(basename)

    return bool(sigma_tokens & existing_tokens)

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

def _aggregate_by_name(docs: list[Document]) -> dict[str, list[Document]]:
    groups: dict[str, list[Document]] = {}
    for d in docs:
        name = d.metadata.get("decoder_name")
        if not name:
            continue
        groups.setdefault(name, []).append(d)
    return groups


def _build_aggregated_decoder(name: str, docs: list[Document]) -> Document:
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
    if not name:
        return None
    chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": name})
    docs = db.similarity_search("", k=k, filter=chroma_filter)
    if not docs:
        return None
    return _build_aggregated_decoder(name, docs)


def get_child_decoders(parent_name: str, db, k: int = DECODER_VARIANT_FETCH_K) -> dict[str, Document]:
    if not parent_name:
        return {}
    chroma_filter = build_chroma_filter({"type": "decoder", "parent_decoder": parent_name})
    raw_docs = db.similarity_search("", k=k, filter=chroma_filter)
    groups = _aggregate_by_name(raw_docs)
    return {name: _build_aggregated_decoder(name, docs) for name, docs in groups.items()}


def _lookup_exact_decoder(platform: str, service: str | None, category: str | None,
                           expected_decoder: str, db) -> Document | None:
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

    initial_doc = _lookup_exact_decoder(platform, service, category, expected_decoder, db)

    if not initial_doc:
        doc, log = _fallback_similarity_decoder(platform, expected_decoder, sigma_fields, db, log)
        log["decoder_exists"] = doc is not None
        return doc, log

    log["decoder_exists"] = True
    log["initial_match"] = initial_doc.metadata.get("decoder_name")
    initial_fields = initial_doc.metadata.get("extracted_fields") or []
    log["initial_extracted_fields"] = initial_fields

    if not sigma_fields:
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

    children = get_child_decoders(log["initial_match"], db)
    log["has_children"] = len(children) > 0

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

    best_doc, best_score, best_matched, best_missing, best_name, best_is_child = max(
        candidates, key=lambda c: (c[1], c[5])
    )

    if best_score > 0:
        log["selected_decoder"] = best_name
        log["selection_reason"] = "child_decoder_field_match" if best_is_child else "exact_match_partial_fields"
        log["has_compatible_fields"] = True
        return best_doc, log

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


def _build_field_mapping_prompt_block(sigma_fields: list[str], platform: str, decoder_name: str) -> str:
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