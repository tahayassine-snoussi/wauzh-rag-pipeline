"""
Sigma -> Wazuh Retrieval & Generation Pipeline
================================================
Converts Sigma rules to Wazuh XML using SigWaz, Filtered RAG, LLM, ValidatorAgent.
"""

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document
from validator import ValidatorAgent
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

logger = setup_logger("retrieval", level="INFO")

GENAI_API_KEY = os.getenv("GENAI_API_KEY")
client = genai.Client(api_key=GENAI_API_KEY)

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
    sigma = yaml.safe_load(yaml_content)
    logsource = sigma.get("logsource", {})
    category = logsource.get("category", "unknown")
    product = logsource.get("product", "unknown")

    PLATFORM_MAP = {
        "webserver": "web", "apache": "web", "nginx": "web", "iis": "web",
        "sysmon": "windows", "security": "windows", "windows": "windows",
        "linux": "linux", "auditd": "linux", "ssh": "linux",
    }
    platform = PLATFORM_MAP.get(category, PLATFORM_MAP.get(product, "unknown"))

    DECODER_MAP = {
        "webserver": "web-accesslog",
        "apache": "apache-accesslog",
        "sysmon": "windows-sysmon",
        "security": "windows-security",
    }
    expected_decoder = DECODER_MAP.get(category, DECODER_MAP.get(product, "unknown"))

    return {
        "platform": platform,
        "expected_decoder": expected_decoder,
        "logsource_category": category,
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
    # PROBLEM 6 FIX: Capture similarity scores from ChromaDB and store in metadata
    results_with_scores = db.similarity_search_with_score(query, k=k, filter=chroma_filter)
    documents = []
    for doc, score in results_with_scores:
        doc.metadata["similarity"] = score
        documents.append(doc)
    return documents


def get_decoder_from_db(decoder_name: str, db) -> Document | None:
    chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": decoder_name})
    results = db.similarity_search("", k=1, filter=chroma_filter)
    return results[0] if results else None


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


def generate_decoder(sigma_info: dict, yaml_rule: str) -> tuple[str, list[str], dict]:
    platform = sigma_info["platform"]
    category = sigma_info["logsource_category"]
    sigma_fields = sigma_info.get("sigma_fields", [])

    logger.info(f"GENERATING decoder for {platform}+{category} (needs fields: {sigma_fields})")

    prompt = f"""You are an expert Wazuh decoder engineer. Generate a decoder XML.

SIGMA LOGSOURCE: product={platform}, category={category}
FIELDS NEEDED: {sigma_fields}

FULL SIGMA RULE:
{yaml_rule}

REQUIREMENTS:
1. Root element: <decoder name="{platform}_{category}">
2. MUST extract ALL fields: {sigma_fields}
3. Include <prematch> for log identification
4. Use <regex> with named groups OR <order> for field extraction
5. For Linux process_creation: use auditd format (type=EXECVE, a0=, a1=...) or syslog
6. Map Sigma fields: "Image"->executable path, "CommandLine"->full command
7. Valid Wazuh decoder XML only

Return ONLY the XML. No explanations."""

    interaction = client.interactions.create(model="gemini-3.5-flash", input=prompt)
    output = interaction.output_text

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

    covered, missing, mapped = [], [], {}
    for sf in sigma_fields:
        sf_lower = sf.lower()
        found = False
        for ef in extracted_fields:
            ef_lower = ef.lower()
            if (sf_lower in ef_lower or ef_lower in sf_lower or
                sf_lower.replace("image", "command") in ef_lower):
                covered.append(sf)
                mapped[sf] = ef
                found = True
                break
        if not found:
            missing.append(sf)

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
             generated_parent=None, field_mapping=None) -> str:
    iteration = "1st" if reviews is None else f"retry ({len(reviews)} review(s))"

    rules_context = format_documents(results, "Retrieved Wazuh Rules")
    parents_context = format_documents(parents, "Parent Rules")
    decoders_context = format_documents(decoders, "Decoders")

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

{reviews_section}

CRITICAL CONSTRAINTS:
1. Wrap in <group name="..."> — never bare <rule>
2. Static fields use dedicated tags: <url>, <srcip>, <dstip>, <user>, <id>, <protocol>, <action>, <status>
3. <srcip>/<dstip> are for literal IPs only
4. No <field name="full_log"> for log type context
5. Single-line regex only
6. Same-field tags = AND logic — use | for OR
7. Only use fields the decoder extracts
8. type="pcre2" required for regex metacharacters
9. <if_sid> MUST exist in parents_context

Return ONLY the final Wazuh XML rule."""

    interaction = client.interactions.create(model="gemini-3.5-flash", input=prompt)
    return interaction.output_text


def main(yaml_rule: str | None = None):
    if yaml_rule is None:
        yaml_rule = """
title: Terminate Linux Process Via Kill
id: 64c41342-6b27-523b-5d3f-c265f3efcdb3
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/kill'
            - '/killall'
            - '/pkill'
            - '/xkill'
    condition: selection
level: medium
"""

    sigma_info = classify_sigma_rule(yaml_rule)
    platform = sigma_info["platform"]
    expected_decoder = sigma_info["expected_decoder"]

    wazuh_rule = convert_sigma_to_xml(yaml_rule)
    results = retrieve_filtered(wazuh_rule, platform, DB, k=5)
    parents, results = add_parent_rules(results, DB)

    # Step 5: DECODER RESOLUTION
    logger.info("[Step 5/7] Resolving decoder...")

    original_decoder = expected_decoder
    decoder_doc = get_decoder_from_db(expected_decoder, DB)
    decoders = {}
    generated_decoder_xml = None
    generated_parent_xml = None
    generated_parent_id = None
    field_mapping = {}
    is_bootstrap = False

    validator = ValidatorAgent(DB)

    valid_parent_count = sum(1 for d in results if d.metadata.get("parent_valid"))

    # Check if new rule type
    is_new, reason = validator.is_new_rule_type(
        original_decoder, results, valid_parent_count, sigma_info["logsource_category"]
    )

    # Check if decoder is useless (0 fields)
    decoder_useless = False
    if decoder_doc:
        fields = decoder_doc.metadata.get("extracted_fields") or []
        decoder_useless = len(fields) == 0
        if decoder_useless:
            logger.warning(f"Decoder '{expected_decoder}' has ZERO fields")
            is_new = True

    logger.info(f"  Bootstrap check: is_new={is_new}, reason={reason}")

    if is_new:
        logger.warning(">>> BOOTSTRAP MODE <<<")

        decoder_xml, extracted_fields, coverage = generate_decoder(sigma_info, yaml_rule)

        if decoder_xml:
            proposed_name = f"{platform}_{sigma_info['logsource_category']}"
            is_dec_valid, dec_reviews, dec_coverage = validator.validate_decoder(
                decoder_xml, sigma_info.get("sigma_fields", []), proposed_name
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
                              "platform": platform, "extracted_fields": extracted_fields}
                )
            else:
                logger.warning(f"Decoder validation failed: {dec_reviews}")
                expected_decoder = "syslog"
                is_bootstrap = True
        else:
            expected_decoder = "syslog"
            is_bootstrap = True

    elif decoder_doc:
        decoders[expected_decoder] = decoder_doc
        fields = decoder_doc.metadata.get('extracted_fields') or []
        logger.info(f"Using DB decoder: '{expected_decoder}' ({len(fields)} fields)")

    else:
        expected_decoder = "syslog"
        is_bootstrap = True

    # Generate root parent if bootstrap
    if is_bootstrap or not parents:
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

    for iteration in range(MAX_ITERATIONS):
        logger.info(f"--- Attempt {iteration + 1}/{MAX_ITERATIONS} ---")

        generated = llm_call(
            results, parents, decoders, wazuh_rule, yaml_rule, reviews,
            is_bootstrap=is_bootstrap,
            generated_decoder=generated_decoder_xml,
            generated_parent=generated_parent_xml,
            field_mapping=field_mapping
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
    if_sid = re.search(r'<if_sid>(\d+)</if_sid>', result)
    logger.info(f"Rule if_sid:      {if_sid.group(1) if if_sid else 'NONE'}")
    uses_fields = '<field name=' in result and 'full_log' not in result
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