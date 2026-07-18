from langchain_chroma import Chroma
from dotenv import load_dotenv
from langchain_community.embeddings import HuggingFaceEmbeddings

import subprocess
import tempfile
import os
import re
import sys
from glob import glob
import xml.etree.ElementTree as ET
from langchain_core.documents import Document

load_dotenv()
from google import genai

key = os.getenv("GENAI_API_KEY")
client = genai.Client(api_key=key)

# -----------------------------
# Embedding model
# -----------------------------
embedding_model = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={
        "batch_size": 32
    }
)

# -----------------------------
# Chroma database
# -----------------------------
persistent_directory = "db/chroma_db"
db = Chroma(
    persist_directory=persistent_directory,
    embedding_function=embedding_model,
    collection_metadata={
        "hnsw:space": "cosine"
    },
    collection_name="rules_collection"
)

# -----------------------------
# Sigma -> Wazuh converter
# -----------------------------
def extract_xml(output):

    match = re.search(
        r"(<group[\s\S]*?</group>)",
        output
    )

    if not match:
        raise Exception(
            "No XML found in converter output\n\n"
            + output
        )

    return match.group(1)

def convert_sigma_to_xml(yaml_content):

    with tempfile.NamedTemporaryFile(
        suffix=".yaml",
        mode="w",
        delete=False
    ) as f:

        f.write(yaml_content)
        sigma_file = f.name


    try:

        SIGWAZ_PATH = os.path.join(
            os.path.dirname(__file__),
            "..",
            "sigwaz-cli",
            "sigwaz.py"
        )


        result = subprocess.run(
            [
                sys.executable,
                SIGWAZ_PATH,
                "convert",
                sigma_file
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={
                **os.environ,
                "PYTHONIOENCODING": "utf-8"
            }
        )


        if result.returncode != 0:
            raise Exception(
                result.stderr
            )

        output = result.stdout + "\n" + result.stderr

        skip = re.search(r"Skipped:\s*(.*)", output)

        if skip:
            raise Exception(
                f"SigWaz skipped this Sigma rule.\nReason: {skip.group(1)}"
            )

        xml_rule = extract_xml(output)


        return xml_rule


    finally:

        os.remove(
            sigma_file
        )

# -----------------------------
# Add parent rules
# -----------------------------
def add_parent_rules(documents, db):
    """
    For each retrieved rule:
      - Extract its parent rule ID (<if_sid>)
      - Store the parent ID in the rule metadata
      - Retrieve the parent rule only once

    Returns:
        parents (dict): {parent_rule_id: parent_document}
        documents (list): Updated documents with enriched metadata
    """

    parents = {}
    for doc in documents:

        content = doc.page_content
        parent_match = re.search(r"<if_sid>(\d+)</if_sid>", content)

        if not parent_match:
            doc.metadata["parent_rule"] = None
            continue

        parent_id = parent_match.group(1)

        # Save relationship in metadata
        doc.metadata["parent_rule"] = parent_id

        # Already retrieved this parent
        if parent_id in parents:
            continue

        parent_results = db.similarity_search(
            "",
            k=1,
            filter={
                "rule_id": parent_id
            }
        )
        if parent_results:
            parents[parent_id] = parent_results[0]

    return parents, documents

# -----------------------------
# Retriever
# -----------------------------
retriever = db.as_retriever(
    search_type="similarity_score_threshold",
    search_kwargs={
        "k": 2,
        "score_threshold": 0.3
    }
)

# -----------------------------
# Test Sigma rule
# -----------------------------
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


# -----------------------------
# Load Wazuh decoders
# -----------------------------
def load_decoders(decoder_path="data/decoders/*.xml"):

    decoder_index = {}

    for file in glob(decoder_path):

        try:

            with open(
                file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                content = f.read()


        except Exception as e:
            print(
                f"Failed reading {file}: {e}"
            )
            continue


        # Extract every decoder block
        decoder_blocks = re.findall(
            r"<decoder.*?</decoder>",
            content,
            re.DOTALL
        )


        for block in decoder_blocks:


            name_match = re.search(
                r'<decoder name="([^"]+)"',
                block
            )


            if not name_match:
                continue


            name = name_match.group(1)


            if name in decoder_index:
                continue


            decoder_index[name] = Document(
                page_content=block,
                metadata={
                    "decoder_name": name,
                    "source_file": file
                }
            )


    return decoder_index

# -----------------------------
# Add rule decoder
# -----------------------------
def add_decoders(results, decoder_index):

    decoders = {}

    for doc in results:

        decoder_match = re.search(
            r"<decoded_as>(.*?)</decoded_as>",
            doc.page_content
        )

        if not decoder_match:
            continue

        decoder_name = decoder_match.group(1)

        doc.metadata["decoder"] = decoder_name

        if decoder_name in decoder_index:
            decoders[decoder_name] = decoder_index[decoder_name]

    return decoders, results


def format_documents(documents, title):
    """
    Format a dictionary/list of LangChain Documents
    into a readable LLM context.
    """

    output = f"\n===== {title} =====\n"

    if not documents:
        output += "None found\n"
        return output


    if isinstance(documents, dict):

        for key, doc in documents.items():

            output += f"""

--- {key} ---

Metadata:
{doc.metadata}

Content:
{doc.page_content}

"""

    else:

        for doc in documents:

            output += f"""

Metadata:
{doc.metadata}

Content:
{doc.page_content}

"""


    return output


def llm_call(results, parents, decoders, wazuh_rule, yaml_rule):
    
    rules_context = format_documents(results, "Retrieved Wazuh Rules")
    parents_context = format_documents(parents, "Parent Rules")
    decoders_context = format_documents(decoders, "Decoders")
    prompt = f"""

You are an expert Wazuh detection engineer with deep knowledge of the Wazuh ruleset XML schema, decoder field extraction, and rule evaluation engine.

Your task is to improve a Wazuh rule generated automatically from a Sigma rule.

You will receive:

1. The original Sigma rule.
2. The Wazuh XML rule generated by SigWaz.
3. Similar Wazuh rules from a knowledge base (rules_context).
4. Parent rules referenced through <if_sid> (parents_context).
5. Relevant decoders (decoders_context).

Your objective:

- Validate whether the generated Wazuh rule correctly represents the Sigma detection logic.
- Fix incorrect Wazuh fields.
- Fix incorrect rule hierarchy.
- Use existing Wazuh rules as examples.
- Respect existing parent-child relationships.
- Verify that referenced decoders support the fields used by the rule.
- Remove unnecessary elements.
- Do not invent unsupported Wazuh syntax.
- Keep the rule compatible with Wazuh XML syntax.

========================

ORIGINAL SIGMA RULE

{yaml_rule}


========================

GENERATED WAZUH RULE

{wazuh_rule}


{rules_context}


{parents_context}


{decoders_context}


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
   When the pattern contains regex metacharacters (., *, +, ?, |, (, ), [, ], ^, $, \s, \d, etc.), you MUST include type="pcre2" on the tag.
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

Do not include:
- explanations
- markdown
- comments outside the XML
- analysis

"""

    interaction = client.interactions.create(
        model="gemini-3.5-flash",
        input=prompt
    )
    print("*"*50)
    print(f"prompt sent to LLM, : {prompt}")
    print("*"*50)
    print("*"*50)
    print(interaction.output_text)


def main():

    print("\n========================")
    print("Converting Sigma -> Wazuh")
    print("==========================\n")
    wazuh_rule = convert_sigma_to_xml(yaml_rule)
    print(wazuh_rule)

    print("\n========================")
    print("RAG Retrieval")
    print("==========================\n")
    results = retriever.invoke(wazuh_rule)

    # Add parent rules
    parents,results = add_parent_rules(results, db)

    # -----------------------------
    # Display
    # -----------------------------
    for i, doc in enumerate(results, 1):
        print(f"\n====== RESULT {i} ======\n")
        print(doc.page_content)
        print("\nMETADATA:")
        print(doc.metadata)
    
    
    print("\n========================")
    print("Add decoders")
    print("==========================\n")
    decoder_index = load_decoders()
    decoders, results = add_decoders(results, decoder_index)

    print("\n========================")
    print("LLM Call")
    print("==========================\n")
    llm_call(results, parents, decoders, wazuh_rule, yaml_rule)

if __name__ == "__main__":
    main()