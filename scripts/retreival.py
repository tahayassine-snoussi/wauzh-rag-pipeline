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
        "k": 5,
        "score_threshold": 0.3
    }
)

# -----------------------------
# Test Sigma rule
# -----------------------------
yaml_rule = """
title: SQL Injection Strings In URI
id: 5513deaf-f49a-46c2-a6c8-3f111b5cb453
status: stable
description: Detects potential SQL injection attempts via GET requests in access logs.

tags:
    - attack.initial-access
    - attack.t1190

logsource:
    category: webserver


detection:

    selection:
        cs-method: GET


    keywords:
        - UNION SELECT
        - select database()
        - information_schema.tables
        - concat_ws(
        - order by


    condition:
        selection and keywords


level: high
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

You are an expert Wazuh detection engineer.

Your task is to improve a Wazuh rule generated automatically from a Sigma rule.

You will receive:

1. The original Sigma rule.
2. The Wazuh XML rule generated by SigWaz.
3. Similar Wazuh rules from a knowledge base.
4. Parent rules referenced through <if_sid>.
5. Relevant decoders.

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