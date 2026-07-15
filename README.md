# Wazuh-RAG: Intelligent Sigma-to-Wazuh Rule Conversion

> A Retrieval-Augmented Generation (RAG) pipeline that converts generic Sigma detection rules into production-ready, context-aware Wazuh XML rules by leveraging your existing Wazuh knowledge base.

---

## Overview

Wazuh-RAG bridges the gap between vendor-agnostic Sigma rules and vendor-specific Wazuh implementations. Instead of blindly translating Sigma YAML to Wazuh XML, this system retrieves relevant existing rules, resolves their parent hierarchies, and validates decoder compatibility to provide an LLM with complete context—producing accurate, syntactically correct, and deployment-ready Wazuh rules.

---

## The Problem

Sigma rules are designed to be generic. When converting them to Wazuh XML, several challenges arise:

- **Field name mismatches**: Sigma fields (e.g., `cs-method`) often do not map 1:1 to Wazuh fields extracted by decoders.
- **Broken rule hierarchy**: Wazuh relies on parent-child relationships via `<if_sid>`. Auto-generated rules often miss or misreference these, causing silent failures.
- **Decoder incompatibility**: A rule may reference fields that the assigned decoder does not actually extract, making the rule useless.
- **Syntax drift**: Auto-generated XML frequently contains unsupported or malformed Wazuh syntax.

---

## The Solution: A Two-Stage RAG Pipeline

### Stage 1: Ingestion (`scripts/ingestion.py`)

Builds a semantic, searchable knowledge base from your existing Wazuh deployment.

| Step | Action | Value |
|------|--------|-------|
| **Load** | Reads `*.xml` rule files from `data/rules/` | Captures your actual, battle-tested rules |
| **Extract** | Uses regex to isolate individual `<rule>...</rule>` blocks and preceding XML comments | Preserves atomic rule logic and human-written category labels |
| **Categorize** | Cleans short XML comments (e.g., `<!-- SQL Injection -->`) and attaches them as `category` metadata | Enables semantic filtering and improves retrieval relevance |
| **Embed** | Encodes each rule with `sentence-transformers/all-MiniLM-L6-v2` | Creates dense vector representations for semantic similarity search |
| **Store** | Persists vectors in **ChromaDB** with cosine similarity | Enables fast, local, offline retrieval of semantically similar rules |

**Why this matters:** Your existing Wazuh rules are the best source of truth for how your organization writes detection logic. By embedding them, we turn your ruleset into a retrivable knowledge base.

---

### Stage 2: Retrieval & Generation (`scripts/retrieval.py`)

Converts a Sigma rule into an optimized, validated Wazuh rule.

| Step | Action | Value |
|------|--------|-------|
| **Convert** | Sends Sigma YAML to **SigWaz CLI** to generate draft Wazuh XML | Provides a baseline translation to work from |
| **Retrieve** | Performs similarity search against ChromaDB (k=5, threshold=0.3) | Finds the most relevant existing Wazuh rules as examples |
| **Resolve Parents** | For each retrieved rule, extracts `<if_sid>`, fetches the parent rule from the DB, and injects it into context | Ensures the generated rule respects Wazuh's hierarchical rule tree |
| **Resolve Decoders** | Indexes `data/decoders/`, extracts `<decoder>` blocks, and loads those referenced by `<decoded_as>` | Validates that the fields used in the rule are actually supported by the decoder |
| **Generate** | Feeds Sigma rule + draft XML + similar rules + parents + decoders into **Gemini 3.5 Flash** | LLM validates syntax, fixes field names, corrects hierarchy, and outputs final XML |

---

## Why Each Component Matters

### Why RAG? Why not just prompt an LLM?

LLMs hallucinate vendor-specific syntax and field names. By retrieving **real, working Wazuh rules** from your own environment, the model has concrete, trusted examples to imitate. This dramatically reduces hallucination and ensures the output matches your actual Wazuh deployment style and version.

### Why Parent Rules?

Wazuh rules are inherently hierarchical. A child rule uses `<if_sid>` to link to a parent rule ID. This parent defines:
- Which log source or decoder the child applies to
- The rule group (e.g., `web`, `syslog`, `windows`)
- The base severity or classification

If the parent is missing, incorrect, or incompatible:
- The child rule will **never trigger**
- The Wazuh manager may **fail to load** the ruleset
- Rule grouping and correlation break

Our pipeline automatically resolves `<if_sid>` references and includes the full parent rule in the LLM prompt, forcing the model to respect the existing hierarchy.

### Why Decoders?

Decoders are Wazuh's log parsers. They take raw logs (syslog, JSON, Windows EventLog, etc.) and extract structured fields into the Wazuh event format. A Wazuh rule references a specific decoder via `<decoded_as>`.

**Critical insight:** If a rule checks for `fieldX`, but the assigned decoder does not extract `fieldX`, the rule will **silently fail** every time.

By indexing all decoders and injecting the relevant ones into the LLM context, we allow the model to verify that every field referenced in the generated rule is actually produced by the referenced decoder. If not, the LLM can remap the field or suggest a different decoder.

---

## Project Structure

```
WAZUH-RAG/
├── data/
│   ├── decoders/          # Wazuh decoder XML files (your log parsers)
│   └── rules/             # Wazuh rule XML files (your knowledge base)
├── db/
│   └── chroma_db/         # Persistent Chroma vector store (auto-generated)
├── scripts/
│   ├── ingestion.py       # Stage 1: Ingest & embed Wazuh rules
│   └── retrieval.py       # Stage 2: Convert Sigma → Wazuh via RAG
├── sigwaz-cli/            # Sigma-to-Wazuh converter tool (external dependency)
├── .env                   # API keys and configuration
├── requirements.txt       # Python dependencies
└── README.md
```

---

## Prerequisites

- **Python 3.10+**
- **[SigWaz CLI](https://github.com/...)**: Must be cloned/installed in `sigwaz-cli/`
- **Wazuh rule files** (`*.xml`) placed in `data/rules/`
- **Wazuh decoder files** (`*.xml`) placed in `data/decoders/`
- **Google GenAI API key**: Required for Gemini 3.5 Flash

---

## Installation

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd WAZUH-RAG

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env and add your GENAI_API_KEY
```

### Environment Variables (`.env`)

```env
GENAI_API_KEY=your_google_genai_api_key_here
```

---

## Usage

### Step 1: Ingest Your Wazuh Rules

Populate the vector database with your existing Wazuh rules:

```bash
cd scripts
python ingestion.py
```

**What happens:**
- Scans `data/rules/` for `*.xml` files
- Extracts each `<rule>` block and its preceding category comment
- Embeds and stores them in `db/chroma_db/`

**Expected output:**
```
************************
 Starting the ingestion pipeline...
************************
****
 Loading files...
****
...
Extracted 1,247 rules
****
 Embedding files...
****
finished creating the vector store and persisting it to disk at db/chroma_db
```

> **Note:** Run this whenever you update your Wazuh ruleset to keep the knowledge base current.

---

### Step 2: Convert a Sigma Rule

Edit `scripts/retrieval.py` and set the `yaml_rule` variable to your Sigma rule, then run:

```bash
python retrieval.py
```

**What happens:**
1. Converts your Sigma YAML to draft Wazuh XML via SigWaz
2. Retrieves the 5 most semantically similar existing Wazuh rules
3. Resolves parent rules via `<if_sid>` and fetches them
4. Loads relevant decoders via `<decoded_as>`
5. Sends the full context to Gemini and prints the **final, validated Wazuh XML rule**

**The output is a single, clean XML rule ready for deployment.**

---

## How It Works (Detailed Flow)

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Sigma Rule     │────▶│   SigWaz CLI     │────▶│ Draft Wazuh XML │
│   (YAML)        │     │  (Initial Conv)  │     │  (Often flawed) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Final Wazuh    │◀────│  Gemini 3.5 Flash│◀────│  RAG Context    │
│   XML Rule      │     │   (Validation &  │     │  (Rules +       │
│  (Production)   │     │    Refinement)   │     │  Parents +      │
└─────────────────┘     └──────────────────┘     │  Decoders)      │
                                                 └─────────────────┘
                                                          ▲
                                                          │
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Wazuh Rule     │────▶│  ChromaDB Vector │────▶│  Semantic       │
│   Files (.xml)  │     │     Store        │     │  Search (k=5)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

---

## Customization

| Parameter | Location | Default | Description |
|-----------|----------|---------|-------------|
| `k` | `retrieval.py` → `retriever` | `5` | Number of similar rules to retrieve |
| `score_threshold` | `retrieval.py` → `retriever` | `0.3` | Minimum cosine similarity for retrieval |
| `model_name` | Both scripts | `all-MiniLM-L6-v2` | Sentence transformer for embeddings |
| `collection_name` | Both scripts | `rules_collection` | Chroma collection identifier |
| `persist_directory` | Both scripts | `db/chroma_db` | Where the vector DB is stored |

---

## Requirements

See [`requirements.txt`](requirements.txt) for the full dependency list.

Core dependencies:
- **LangChain** (`langchain-core`, `langchain-community`, `langchain-chroma`) — Document processing and vector store integration
- **ChromaDB** (`chromadb`) — Local vector database for semantic search
- **Sentence-Transformers** (`sentence-transformers`) — Local embedding model (no OpenAI API needed for embeddings)
- **Google GenAI** (`google-genai`) — Gemini API client for rule generation
- **python-dotenv** — Secure environment variable management

---

## License

MIT
