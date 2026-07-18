"""
Sigma -> Wazuh Retrieval & Generation Pipeline
================================================

Converts Sigma rules to Wazuh XML using:
  1. SigWaz for initial conversion
  2. Filtered RAG for context retrieval
  3. LLM for rule refinement
  4. ValidatorAgent for validation with feedback loop

Usage:
    python retrieval.py

Logs:
    logs/retrieval.log  (persistent)
    Console output     (colored, real-time)
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

# Import shared logger
from logger import setup_logger

# ---------------------------------------------------------------------------
# Setup logger
# ---------------------------------------------------------------------------
logger = setup_logger("retrieval", level="INFO")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GENAI_API_KEY = os.getenv("GENAI_API_KEY")
client = genai.Client(api_key=GENAI_API_KEY)

logger.info("Initializing embedding model and ChromaDB connection")
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
logger.info("ChromaDB connected successfully")

MAX_ITERATIONS = 3

# ---------------------------------------------------------------------------
# Sigma Classification
# ---------------------------------------------------------------------------

def classify_sigma_rule(yaml_content: str) -> dict:
    """
    Extract platform and expected decoder from Sigma YAML.

    Returns:
        {"platform": "web|windows|linux|unknown",
         "expected_decoder": "web-accesslog|...",
         "logsource_category": "webserver|..."}
    """
    logger.debug("Parsing Sigma YAML for classification")
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

    logger.info(f"Sigma classified: platform={platform}, decoder={expected_decoder}, category={category}")
    return {
        "platform": platform,
        "expected_decoder": expected_decoder,
        "logsource_category": category,
    }

# ---------------------------------------------------------------------------
# SigWaz Converter
# ---------------------------------------------------------------------------

def extract_xml(output: str) -> str:
    match = re.search(r"(<group[\s\S]*?</group>)", output)
    if not match:
        raise Exception(f"No XML found in converter output\n\n{output}")
    return match.group(1)


def convert_sigma_to_xml(yaml_content: str) -> str:
    logger.info("Converting Sigma to Wazuh XML using SigWaz...")
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(yaml_content)
        sigma_file = f.name

    try:
        SIGWAZ_PATH = os.path.join(
            os.path.dirname(__file__), "..", "sigwaz-cli", "sigwaz.py"
        )
        logger.debug(f"SigWaz path: {SIGWAZ_PATH}")

        result = subprocess.run(
            [sys.executable, SIGWAZ_PATH, "convert", sigma_file],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        if result.returncode != 0:
            logger.error(f"SigWaz failed: {result.stderr}")
            raise Exception(result.stderr)

        output = result.stdout + "\n" + result.stderr
        skip = re.search(r"Skipped:\s*(.*)", output)
        if skip:
            logger.error(f"SigWaz skipped: {skip.group(1)}")
            raise Exception(f"SigWaz skipped this Sigma rule.\nReason: {skip.group(1)}")

        xml_rule = extract_xml(output)
        logger.info(f"SigWaz conversion successful ({len(xml_rule)} chars)")
        logger.debug(f"SigWaz output:\n{xml_rule[:500]}...")
        return xml_rule

    finally:
        os.remove(sigma_file)

# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def retrieve_filtered(query: str, platform: str, db, k: int = 5) -> list[Document]:
    """Semantic search with metadata filtering by platform."""
    logger.info(f"Retrieving rules (platform={platform}, k={k})")

    filter_dict = {"type": "rule"}
    if platform != "unknown":
        filter_dict["platform"] = platform

    chroma_filter = build_chroma_filter(filter_dict)
    logger.debug(f"ChromaDB filter: {chroma_filter}")

    results = db.similarity_search(query, k=k, filter=chroma_filter)
    logger.info(f"Retrieved {len(results)} rules")

    for i, doc in enumerate(results[:3]):
        logger.debug(f"  Result {i+1}: ID={doc.metadata.get('rule_id')}, "
                     f"platform={doc.metadata.get('platform')}, "
                     f"category={doc.metadata.get('category', 'N/A')[:30]}")

    return results


def get_decoder_from_db(decoder_name: str, db) -> Document | None:
    """Lookup decoder by exact name."""
    logger.debug(f"Looking up decoder: {decoder_name}")
    chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": decoder_name})
    results = db.similarity_search("", k=1, filter=chroma_filter)

    if results:
        logger.info(f"Found decoder: {decoder_name}")
        return results[0]
    logger.warning(f"Decoder not found: {decoder_name}")
    return None


def get_rule_by_id(rule_id: str, db) -> Document | None:
    """Lookup rule by exact ID."""
    logger.debug(f"Looking up rule by ID: {rule_id}")
    chroma_filter = build_chroma_filter({"type": "rule", "rule_id": rule_id})
    results = db.similarity_search("", k=1, filter=chroma_filter)

    if results:
        logger.debug(f"Found rule: {rule_id}")
        return results[0]
    logger.debug(f"Rule not found: {rule_id}")
    return None


def add_parent_rules(documents: list[Document], db) -> tuple[dict, list[Document]]:
    """Lookup parents for retrieved rules and validate them."""
    logger.info("Looking up parent rules...")
    parents = {}
    valid_parents = 0
    invalid_parents = 0

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
            is_valid = has_children or level <= 2
            doc.metadata["parent_valid"] = is_valid
            doc.metadata["parent_level"] = level

            if is_valid:
                valid_parents += 1
            else:
                invalid_parents += 1
                logger.warning(f"Parent {parent_id} is not a valid grouping rule (level={level}, children={has_children})")
        else:
            doc.metadata["parent_valid"] = False
            doc.metadata["parent_error"] = f"Parent {parent_id} not found"
            invalid_parents += 1
            logger.warning(f"Parent {parent_id} not found in DB")

    logger.info(f"Parent lookup complete: {len(parents)} unique parents "
                f"({valid_parents} valid, {invalid_parents} invalid)")
    return parents, documents

# ---------------------------------------------------------------------------
# Context Formatting
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# LLM Call
# ---------------------------------------------------------------------------

def llm_call(
    results: list[Document],
    parents: dict,
    decoders: dict,
    wazuh_rule: str,
    yaml_rule: str,
    reviews: list[str] | None = None
) -> str:
    """
    Call the LLM to generate/refine a Wazuh rule.
    """
    iteration = "1st" if reviews is None else f"retry (with {len(reviews)} review(s))"
    logger.info(f"Calling LLM ({iteration})...")

    rules_context = format_documents(results, "Retrieved Wazuh Rules")
    parents_context = format_documents(parents, "Parent Rules")
    decoders_context = format_documents(decoders, "Decoders")

    reviews_section = ""
    if reviews:
        reviews_section = f"""
========================

PREVIOUS VALIDATION ERRORS — YOU MUST FIX THESE

{"\n".join(f"- {r}" for r in reviews)}

Do not ignore these errors. Fix every one before generating the rule again.
Pay special attention to wrong if_sid values and invalid field names.
"""
        logger.debug(f"Adding {len(reviews)} review(s) to prompt")

    prompt = f"""
You are an expert Wazuh detection engineer with deep knowledge of the Wazuh ruleset XML schema, decoder field extraction, and rule evaluation engine.

Your task is to improve a Wazuh rule generated automatically from a Sigma rule.

========================

ORIGINAL SIGMA RULE

{yaml_rule}

========================

GENERATED WAZUH RULE

{wazuh_rule}

{rules_context}

{parents_context}

{decoders_context}

{reviews_section}

========================

CRITICAL RULE GENERATION CONSTRAINTS

1. GROUP WRAPPER
   Every rule MUST be wrapped in a <group name="..."> tag. Do not emit a bare <rule> without a parent <group>.
   Example: <group name="web,accesslog,sql_injection,"> ... </group>

2. STATIC FIELD TAGS — NEVER USE <field name="..."> FOR THESE
   Wazuh decoders extract certain fields as static internal values. These MUST use their dedicated XML tags:
   - url        -> use <url>          (NEVER <field name="url">)
   - srcip      -> use <srcip>        (NEVER <field name="srcip">)
   - dstip      -> use <dstip>        (NEVER <field name="dstip">)
   - user       -> use <user>         (NEVER <field name="user">)
   - id         -> use <id>           (NEVER <field name="id">)
   - protocol   -> use <protocol>     (NEVER <field name="protocol">)
   - action     -> use <action>       (NEVER <field name="action">)
   - status     -> use <status>       (NEVER <field name="status">)
   Using <field name="..."> for any static field causes a fatal error: "Field 'X' is static."

3. <srcip> AND <dstip> ARE NOT REGEX TAGS
   The <srcip> and <dstip> tags are reserved for literal IP address or CIDR matching only (e.g., <srcip>192.168.1.0/24</srcip>).
   They do NOT support type="pcre2" or arbitrary regex. Wazuh validates their content as actual IP addresses and will throw "Invalid ip address" if you put regex there.
   For regex-based IP matching (e.g., private IP exclusion), use <field name="srcip"> or <field name="dstip"> (or the specific decoder field like eventdata.destinationIp), never the bare <srcip> or <dstip> tags.

4. NO REDUNDANT <field name="full_log"> SCOPING
   Do NOT emit <field name="full_log"> to establish log type context (e.g., checking for "GET", "POST", "EventID", "ProcessName").
   The parent <if_sid> already establishes the event type and source. Adding full_log conditions creates fragile AND logic that often fails due to whitespace, quote handling, or encoding differences, causing the rule to load but never fire silently.

5. SINGLE-LINE REGEX
   All PCRE2 patterns inside <url>, <field>, <program_name>, or any other tag MUST be emitted on a single line between the opening and closing tags.
   Do not insert newlines, indentation, or extra spaces inside the tag content. XML whitespace becomes literal characters in the regex pattern and breaks matching.

6. SAME-FIELD CONDITIONS = AND LOGIC
   If you emit multiple tags with the same name (e.g., two <field name="full_log"> tags, or two <url> tags), Wazuh evaluates them as logical AND — all must match.
   If the Sigma rule represents OR logic across the same field, combine all patterns into a single tag using regex alternation |.
   Example: <url type="pcre2">pattern1|pattern2|pattern3</url>

7. FIELD NAME VALIDATION
   Only use field names that the provided decoders actually extract. If the decoder does not extract a field, do not invent it in <field name="...">.
   Map Sigma fields to actual Wazuh decoder output fields. When uncertain, use <full_log> as a fallback, but prefer the specific extracted field if it exists.
   IMPORTANT: Platform prefixes matter. The "win." prefix (e.g., win.eventdata.image) is ONLY for Windows EventChannel logs. For Linux Sysmon, Docker, AWS, or other non-Windows sources, use the field name WITHOUT the "win." prefix (e.g., eventdata.image).

8. PCRE2 TYPE ATTRIBUTE
   When the pattern contains regex metacharacters (., *, +, ?, |, (, ), [, ], ^, $, \\s, \\d, etc.), you MUST include type="pcre2" on the tag.
   Without it, Wazuh uses simple substring matching and the metacharacters are treated as literals.

9. if_sid VALIDATION
   You MUST validate the <if_sid> value against the provided parents_context and rules_context.
   - If a retrieved rule from rules_context matches the SAME log source and event type as the Sigma rule, you MAY use its parent rule ID as <if_sid>.
   - If the generated <if_sid> contains IDs that do NOT appear in parents_context, REMOVE them.
   - If NO valid parent exists after validation, OMIT the <if_sid> tag entirely. Emit a standalone rule without <if_sid> rather than inventing parent IDs or keeping generic mappings not confirmed in the retrieved context.
   - NEVER emit <if_sid> values unless those IDs are explicitly present in the provided parents_context.

========================

FINAL OUTPUT REQUIREMENTS

Return ONLY the final Wazuh XML rule.
Do not include explanations, markdown, comments outside the XML, or analysis.
"""

    logger.debug(f"Prompt length: {len(prompt)} chars")

    interaction = client.interactions.create(
        model="gemini-3.5-flash",
        input=prompt
    )

    output = interaction.output_text
    logger.info(f"LLM response received ({len(output)} chars)")
    logger.debug(f"LLM output preview:\n{output[:500]}...")

    return output

# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------

def main(yaml_rule: str | None = None):
    """
    Run the full Sigma -> Wazuh pipeline with validation loop.
    """
    if yaml_rule is None:
        yaml_rule = """
title: Path Traversal Exploitation Attempts
id: 7745c2ea-24a5-4290-b680-04359cb84b35
status: stable
description: Detects path traversal exploitation attempts
references:
    - https://github.com/projectdiscovery/nuclei-templates
    - https://book.hacktricks.xyz/pentesting-web/file-inclusion
author: Subhash Popuri (@pbssubhash), Florian Roth (Nextron Systems), Thurein Oo, Nasreddine Bencherchali (Nextron Systems)
date: 2021-09-25
modified: 2023-08-31
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '../../../../../lib/password'
            - '../../../../windows/'
            - '../../../etc/'
            - '..%252f..%252f..%252fetc%252f'
            - '..%c0%af..%c0%af..%c0%afetc%c0%af'
            - '%252e%252e%252fetc%252f'
    condition: selection
falsepositives:
    - Expected to be continuously seen on systems exposed to the Internet
    - Internal vulnerability scanners
level: medium
"""

    logger.info("=" * 60)
    logger.info("SIGMA -> WAZUH PIPELINE STARTED")
    logger.info("=" * 60)

    # Step 1: Classify Sigma
    logger.info("[Step 1/6] Classifying Sigma rule...")
    sigma_info = classify_sigma_rule(yaml_rule)
    platform = sigma_info["platform"]
    expected_decoder = sigma_info["expected_decoder"]
    logger.info(f"  -> platform={platform}, decoder={expected_decoder}")

    # Step 2: Convert with SigWaz
    logger.info("[Step 2/6] Converting with SigWaz...")
    wazuh_rule = convert_sigma_to_xml(yaml_rule)
    logger.info(f"  -> SigWaz output: {len(wazuh_rule)} chars")

    # Step 3: Filtered RAG retrieval
    logger.info("[Step 3/6] Filtered RAG retrieval...")
    results = retrieve_filtered(wazuh_rule, platform, DB, k=5)
    logger.info(f"  -> Retrieved {len(results)} rules")
    for i, doc in enumerate(results[:3]):
        logger.info(f"     {i+1}. ID={doc.metadata['rule_id']}, "
                    f"valid_parent={doc.metadata.get('parent_valid', 'N/A')}, "
                    f"cat={doc.metadata['category'][:30]}")

    # Step 4: Add parent rules
    logger.info("[Step 4/6] Adding parent rules...")
    parents, results = add_parent_rules(results, DB)
    logger.info(f"  -> Found {len(parents)} unique parents")
    for pid, pdoc in list(parents.items())[:3]:
        logger.info(f"     {pid}: level={pdoc.metadata.get('rule_level')}, "
                    f"children={pdoc.metadata.get('has_children')}")

    # Step 5: Get decoder from DB
    logger.info("[Step 5/6] Fetching decoder from DB...")
    decoder_doc = get_decoder_from_db(expected_decoder, DB)
    decoders = {}
    if decoder_doc:
        decoders[expected_decoder] = decoder_doc
        fields = decoder_doc.metadata.get('extracted_fields') or []
        logger.info(f"  -> Found decoder: {expected_decoder} ({len(fields)} fields)")
        logger.debug(f"     Fields: {fields}")
    else:
        logger.warning(f"  -> Decoder {expected_decoder} NOT FOUND")

    # Step 6: Generation + Validation loop
    logger.info("[Step 6/6] Generation + Validation loop")
    logger.info("=" * 60)

    validator = ValidatorAgent(DB)
    reviews = None
    final_rule = None

    for iteration in range(MAX_ITERATIONS):
        logger.info(f"--- Generation Attempt {iteration + 1}/{MAX_ITERATIONS} ---")

        # Generate
        generated = llm_call(results, parents, decoders, wazuh_rule, yaml_rule, reviews)

        # Extract XML
        try:
            xml_rule = extract_xml(generated)
            logger.info(f"XML extracted successfully ({len(xml_rule)} chars)")
        except Exception as e:
            logger.error(f"XML extraction failed: {e}")
            reviews = [f"Output was not valid Wazuh XML: {e}"]
            continue

        # Validate
        logger.info("Running validator...")
        is_valid, reviews = validator.validate(xml_rule, platform, expected_decoder)

        if is_valid:
            logger.info("VALIDATION PASSED - Rule is production-ready!")
            final_rule = xml_rule
            break
        else:
            logger.warning(f"VALIDATION FAILED - {len(reviews)} error(s):")
            for i, r in enumerate(reviews, 1):
                logger.warning(f"  {i}. {r[:120]}...")
            if iteration < MAX_ITERATIONS - 1:
                logger.info("Regenerating with feedback...")
            else:
                logger.warning("Max iterations reached, returning best effort")

    # Final output
    logger.info("=" * 60)
    if final_rule:
        logger.info("FINAL RULE (VALIDATED)")
    else:
        logger.info("FINAL RULE (BEST EFFORT)")
    logger.info("=" * 60)

    result = final_rule or xml_rule
    logger.info(f"Rule length: {len(result)} chars")
    logger.info(f"\n{result}")

    return result


if __name__ == "__main__":
    main()
