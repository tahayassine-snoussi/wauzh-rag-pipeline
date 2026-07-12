from langchain_chroma import Chroma
from dotenv import load_dotenv
from langchain_community.embeddings import HuggingFaceEmbeddings

import subprocess
import tempfile
import os
import re
import sys

# -----------------------------
# Load environment
# -----------------------------

load_dotenv()


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


print(
    "Collection count:",
    db._collection.count()
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

    enriched_docs = []


    for doc in documents:


        content = doc.page_content


        parent_match = re.search(
            r"<if_sid>(\d+)</if_sid>",
            content
        )


        if parent_match:


            parent_id = parent_match.group(1)


            parent_results = db.similarity_search(
                "",
                k=1,
                filter={
                    "rule_id": parent_id
                }
            )


            if parent_results:


                parent_rule = parent_results[0].page_content


                doc.page_content = f"""

Parent Rule ID: {parent_id}

{parent_rule}


====================

Child Rule:

{content}

"""


        enriched_docs.append(doc)


    return enriched_docs



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
# Convert Sigma
# -----------------------------

print("\n==============================")
print("Converting Sigma -> Wazuh")
print("==============================\n")


wazuh_rule = convert_sigma_to_xml(
    yaml_rule
)


print(wazuh_rule)



# -----------------------------
# Retrieval
# -----------------------------

print("\n==============================")
print("RAG Retrieval")
print("==============================\n")


results = retriever.invoke(
    wazuh_rule
)



# Add parent rules

results = add_parent_rules(
    results,
    db
)



# -----------------------------
# Display
# -----------------------------

for i, doc in enumerate(results, 1):

    print(
        f"\n========== RESULT {i} ==========\n"
    )


    print(
        doc.page_content
    )


    print(
        "\nMETADATA:"
    )


    print(
        doc.metadata
    )



# -----------------------------
# Debug similarity scores
# -----------------------------

print("\n==============================")
print("Similarity Scores")
print("==============================\n")


scores = db.similarity_search_with_score(
    wazuh_rule,
    k=5
)


for doc, score in scores:

    print(
        "Score:",
        score
    )

    print(
        "Metadata:",
        doc.metadata
    )

    print(
        doc.page_content[:300]
    )

    print(
        "---------------------"
    )