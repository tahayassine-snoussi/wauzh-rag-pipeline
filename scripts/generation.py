"""
LLM generation, validation loop, and main orchestration for the Sigma -> Wazuh pipeline.
"""
import os
import re
import yaml

from langchain_core.documents import Document

from utils import (
    DB, GROQ_CLIENT, LLM_CONFIG, MAX_ITERATIONS,
    retry_on_error, XMLExtractionError,
)

from pipeline import (
    classify_sigma_rule,
    classify_process_correlation,
    handle_parent_child_correlation,
    convert_sigma_to_xml,
    retrieve_filtered,
    add_parent_rules,
    resolve_decoder,
    get_decoder_by_name_aggregated,
    generate_root_parent,
    extract_xml,
    format_documents,
    _build_field_mapping_prompt_block,
)
from validator import ValidatorAgent, fields_compatible, field_compatibility_score

from logger import setup_logger
logger = setup_logger("generation", level="INFO")


# =============================================================================
# Decoder / Rule Generation
# =============================================================================

def generate_decoder(sigma_info: dict, yaml_rule: str) -> tuple[str, list[str], dict]:
    platform = sigma_info["platform"]
    service = sigma_info.get("service")
    category = sigma_info.get("category") or sigma_info.get("logsource_category")
    sigma_fields = sigma_info.get("sigma_fields", [])

    decoder_label = service or category or "generic"

    logger.info(f"GENERATING decoder for platform={platform} service={service} "
                f"category={category} (needs fields: {sigma_fields})")

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
3. Use the field name guidance above for <order>/named regex groups whenever a mapping is given for a field
4. Include <prematch> for log identification
5. Use <regex > with named groups OR <order> for field extraction
6. For Linux auditd/process_creation: use auditd format (type=EXECVE, a0=, a1=...)
7. For Linux auditd CommandLine specifically: "audit.execve.a0" through "audit.execve.a7" together reconstruct the full command line
8. Valid Wazuh decoder XML only

Return ONLY the XML. No explanations."""

    interaction = GROQ_CLIENT.chat.completions.create(
        model=LLM_CONFIG.model,
        messages=[{"role": "user", "content": prompt}],
        temperature=LLM_CONFIG.temperature,
        max_tokens=LLM_CONFIG.max_tokens,
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


@retry_on_error(max_retries=3, backoff=2)
def llm_call(results, parents, decoders, wazuh_rule, yaml_rule,
             reviews=None, is_bootstrap=False, generated_decoder=None,
             generated_parent=None, field_mapping=None, sigma_info=None) -> str:
    iteration = "1st" if reviews is None else f"retry ({len(reviews)} review(s))"

    rules_context = format_documents(results, "Retrieved Wazuh Rules")
    parents_context = format_documents(parents, "Parent Rules")
    decoders_context = format_documents(decoders, "Decoders")

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
        lines = "\n".join(f"- {r}" for r in reviews)
        reviews_section = f"""
PREVIOUS VALIDATION ERRORS — FIX THESE:
{lines}
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

    response = GROQ_CLIENT.chat.completions.create(
        model=LLM_CONFIG.model,
        messages=[{"role": "user", "content": prompt}],
        temperature=LLM_CONFIG.temperature,
        max_tokens=LLM_CONFIG.max_tokens,
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
    selection_websphere:
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

    # =====================================================================
    # STEP 0: Parse & classify FIRST (before any conversion)
    # =====================================================================
    sigma = yaml.safe_load(yaml_rule)
    sigma_info = classify_sigma_rule(yaml_rule)
    platform = sigma_info["platform"]
    service = sigma_info.get("service")
    category = sigma_info.get("category")
    expected_decoder = sigma_info["expected_decoder"]
    sigma_fields = sigma_info.get("sigma_fields", [])

    logger.info(f"Classified logsource -> platform={platform}, service={service}, "
                f"category={category}, expected_decoder={expected_decoder}")

    # =====================================================================
    # STEP 0.5: Category C — Parent/Child Correlation (bypasses SigWaz)
    # =====================================================================
    correlation_category = classify_process_correlation(sigma)
    logger.info(f"Process correlation classification: {correlation_category}")
    if correlation_category == "C":
        logger.info(">>> CATEGORY C DETECTED — bypassing single-rule path <<<")
        result = handle_parent_child_correlation(sigma, sigma_info, yaml_rule, DB)

        logger.info("=" * 60)
        logger.info("CATEGORY C FULL RESULTS")
        logger.info("=" * 60)
        for rule in result.get("rules", []):
            logger.info(f"--- {rule['rule_id']} ({rule['type']}) ---")
            logger.info(rule.get("xml", ""))
            logger.info("")
        logger.info("=" * 60)

        return result

    # =====================================================================
    # STEP 1+: Normal pipeline (Category A or B)
    # =====================================================================
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

    # ---- Detailed decoder resolution log -----------------------------------
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

        validator.add_in_memory_decoder(decoder_doc)

        field_mapping = {}
        for sf in sigma_fields:
            for ef in fields:
                if fields_compatible(sf, ef, platform, expected_decoder):
                    field_mapping[sf] = ef
                    break
        logger.info(f"Field mapping for LLM: {field_mapping}")

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