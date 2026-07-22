# Wazuh-RAG Pipeline: Intelligent Sigma-to-Wazuh Rule Conversion

> A production-grade Retrieval-Augmented Generation (RAG) pipeline that converts generic Sigma detection rules into production-ready, context-aware Wazuh XML rules by leveraging your existing Wazuh knowledge base — with built-in validation, bootstrapping for new log sources, and iterative refinement.

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [The Solution: A Hybrid RAG + Validation Pipeline](#the-solution-a-hybrid-rag--validation-pipeline)
- [Pipeline Architecture & Logic Flow](#pipeline-architecture--logic-flow)
  - [Stage 1: Knowledge Base Ingestion](#stage-1-knowledge-base-ingestion)
  - [Stage 2: Sigma-to-Wazuh Conversion](#stage-2-sigma-to-wazuh-conversion)
  - [Stage 3: Filtered RAG Retrieval](#stage-3-filtered-rag-retrieval)
  - [Stage 4: Parent Rule Resolution](#stage-4-parent-rule-resolution)
  - [Stage 5: Decoder Resolution & Bootstrap Mode](#stage-5-decoder-resolution--bootstrap-mode)
  - [Stage 6: LLM Generation](#stage-6-llm-generation)
  - [Stage 7: Validator Agent & Iterative Refinement](#stage-7-validator-agent--iterative-refinement)
- [Why Each Component Matters](#why-each-component-matters)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Step 1: Ingest Your Wazuh Knowledge Base](#step-1-ingest-your-wazuh-knowledge-base)
  - [Step 2: Convert a Sigma Rule](#step-2-convert-a-sigma-rule)
- [The Validator Agent Deep Dive](#the-validator-agent-deep-dive)
- [The Logger System](#the-logger-system)
- [Customization](#customization)
- [Requirements](#requirements)
- [License](#license)

---

## Overview

**Wazuh-RAG** bridges the gap between vendor-agnostic Sigma rules and vendor-specific Wazuh implementations. Instead of blindly translating Sigma YAML to Wazuh XML, this system:

1. **Retrieves** relevant existing rules from your Wazuh deployment via semantic search
2. **Resolves** parent hierarchies and decoder compatibility automatically
3. **Validates** generated output through a dedicated Validator Agent
4. **Bootstraps** entirely new rule types (unknown decoders, new log sources) by generating decoders and parent rules on-the-fly
5. **Iteratively refines** output up to 3 times based on validation feedback

The result is a **production-ready Wazuh XML rule** that is syntactically correct, semantically consistent with your existing ruleset, and compatible with your decoders.

---

## The Problem

Sigma rules are designed to be generic. When converting them to Wazuh XML, several critical challenges arise:

| Challenge | Impact |
|-----------|--------|
| **Field name mismatches** | Sigma fields (e.g., `cs-method`, `Image`, `CommandLine`) often do not map 1:1 to Wazuh fields extracted by decoders |
| **Broken rule hierarchy** | Wazuh relies on parent-child relationships via `<if_sid>`. Auto-generated rules often miss or misreference these, causing **silent failures** |
| **Decoder incompatibility** | A rule may reference fields that the assigned decoder does not extract, making the rule **useless at runtime** |
| **Syntax drift** | Auto-generated XML frequently contains unsupported or malformed Wazuh syntax |
| **Unknown log sources** | Sigma rules for new platforms (e.g., custom applications) have no existing Wazuh rules or decoders to reference |
| **No validation feedback loop** | One-shot generation produces errors that are never caught until deployment |

---

## The Solution: A Hybrid RAG + Validation Pipeline

Our pipeline combines **semantic retrieval**, **structured validation**, and **iterative refinement** to solve these problems holistically.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WAZUH-RAG PIPELINE                                   │
│                    Sigma → Production-Ready Wazuh XML                      │
└─────────────────────────────────────────────────────────────────────────────┘

     ┌─────────────────┐
     │  Sigma Rule     │
     │    (YAML)       │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  SIGWAZ CLI CONVERSION      │  ← External tool (cloned from GitHub)
     │  Initial draft Wazuh XML    │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 1: CLASSIFY           │
     │  • logsource category       │
     │  • platform (web/win/linux) │
     │  • expected decoder family  │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 2: FILTERED RAG       │
     │  Semantic search (k=5)      │
     │  + platform filter          │
     │  + similarity scores        │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 3: PARENT RESOLUTION  │
     │  • Extract <if_sid>         │
     │  • Fetch parent from DB     │
     │  • Validate parent validity │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 4: DECODER RESOLUTION │
     │  • Query decoder from DB    │
     │  • Check field coverage     │
     │  • Bootstrap if missing     │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 5: BOOTSTRAP MODE     │
     │  (if new rule type detected)│
     │  • Generate decoder XML     │
     │  • Validate decoder fields  │
     │  • Generate parent rule     │
     │  • Create field mappings    │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 6: LLM GENERATION     │
     │  Gemini 3.5 Flash           │
     │  • Sigma + SigWaz draft     │
     │  • Retrieved rules          │
     │  • Parents + Decoders       │
     │  • Bootstrap context        │
     │  • Previous errors (retry)  │
     └────────┬────────────────────┘
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 7: VALIDATOR AGENT    │
     │  • XML syntax check         │
     │  • if_sid existence         │
     │  • Parent platform match    │
     │  • Decoder field validation │
     │  • Static field enforcement │
     └────────┬────────────────────┘
              │ FAIL
              │
              ▼
     ┌─────────────────────────────┐
     │  STEP 8: ITERATIVE LOOP     │
     │  • Reviews → prompt         │
     │  • Regenerate (max 3)       │
     │  • Back to Validator        │
     └────────┬────────────────────┘
              │ PASS
              ▼
     ┌─────────────────────────────┐
     │  FINAL OUTPUT               │
     │  Production-ready XML       │
     │  + Decoder (if generated)   │
     │  + Parent (if generated)    │
     └─────────────────────────────┘
```

---

## Pipeline Architecture & Logic Flow

### Stage 1: Knowledge Base Ingestion (`scripts/ingestion.py`)

Builds a semantic, searchable knowledge base from your existing Wazuh deployment.

| Step | Action | Value |
|------|--------|-------|
| **Load** | Reads `*.xml` rule files from `data/rules/` and decoder files from `data/decoders/` | Captures your actual, battle-tested rules and parsers |
| **Extract** | Uses regex to isolate individual `<rule>...</rule>` and `<decoder>...</decoder>` blocks, plus preceding XML comments | Preserves atomic rule logic and human-written category labels |
| **Categorize** | Cleans short XML comments (e.g., `<!-- SQL Injection -->`) and attaches them as `category` metadata; derives platform from path/content | Enables semantic filtering and improves retrieval relevance |
| **Enrich** | Extracts rule IDs, parent IDs, decoder names, MITRE ATT&CK IDs, rule levels, extracted decoder fields | Creates rich metadata for precise filtering and validation |
| **Embed** | Encodes each rule and decoder with `sentence-transformers/all-MiniLM-L6-v2` (batch_size=32) | Creates dense vector representations for semantic similarity search |
| **Store** | Persists vectors in **ChromaDB** with cosine similarity (`hnsw:space: cosine`) | Enables fast, local, offline retrieval of semantically similar rules |

**Why this matters:** Your existing Wazuh rules are the best source of truth for how your organization writes detection logic. By embedding them, we turn your ruleset into a retrievable knowledge base that the LLM can imitate.

**Key features:**
- **Platform detection**: Automatically derives platform (`web`, `windows`, `linux`, `network`, `unknown`) from file paths, categories, and decoder names
- **Logsource mapping**: Maps Wazuh attributes to Sigma `logsource.category` for cross-compatibility
- **Parent-child tracking**: Marks rules with `has_children=True` for hierarchy validation
- **Metadata cleaning**: Converts empty lists to `None` (ChromaDB compatibility fix)

---

### Stage 2: Sigma-to-Wazuh Conversion

The pipeline starts by converting the Sigma YAML rule to an initial Wazuh XML draft using **SigWaz CLI** — an external open-source Sigma-to-Wazuh converter.

> **Note on SigWaz:** The SigWaz CLI tool is cloned from its public GitHub repository and integrated as an external dependency. It provides the baseline translation that our RAG pipeline then validates, corrects, and refines.

```python
# SigWaz is called as a subprocess
subprocess.run(
    [sys.executable, SIGWAZ_PATH, "convert", sigma_file],
    capture_output=True, text=True, ...
)
```

This draft is often flawed (hallucinated fields, broken hierarchy, wrong decoders) — which is exactly why the RAG pipeline exists.

---

### Stage 3: Filtered RAG Retrieval

Performs **platform-aware semantic search** against the ChromaDB knowledge base.

```python
results_with_scores = db.similarity_search_with_score(
    query=wazuh_rule, 
    k=5, 
    filter={"type": "rule", "platform": platform}
)
```

**Why filtered retrieval matters:**
- Without filtering, a Linux Sigma rule might retrieve Windows rules — confusing the LLM
- Platform filtering ensures the LLM only sees relevant, same-platform examples
- Similarity scores are captured and stored in metadata for downstream analysis

**Retrieval logic:**
1. Classify the Sigma rule to determine `platform` and `expected_decoder`
2. Build a ChromaDB-compatible filter (`{"type": "rule", "platform": "linux"}`)
3. Perform semantic search with the SigWaz draft as the query
4. Return top-k documents with similarity scores

---

### Stage 4: Parent Rule Resolution

Wazuh rules are inherently hierarchical. A child rule uses `<if_sid>` to link to a parent rule ID. This parent defines:
- Which log source or decoder the child applies to
- The rule group (e.g., `web`, `syslog`, `windows`)
- The base severity or classification

**The pipeline automatically:**
1. Extracts `<if_sid>` from each retrieved rule
2. Fetches the parent rule from ChromaDB by `rule_id`
3. Validates the parent:
   - Does it exist in the knowledge base?
   - Does its platform match the target platform?
   - Is it a valid grouping rule (`level <= 2` or `has_children=True`)?
4. Injects the full parent rule into the LLM context

**Critical insight:** If the parent is missing, incorrect, or incompatible:
- The child rule will **never trigger**
- The Wazuh manager may **fail to load** the ruleset
- Rule grouping and correlation break

---

### Stage 5: Decoder Resolution & Bootstrap Mode

Decoders are Wazuh's log parsers. They take raw logs and extract structured fields. A Wazuh rule references a specific decoder via `<decoded_as>`.

**Critical insight:** If a rule checks for `fieldX`, but the assigned decoder does not extract `fieldX`, the rule will **silently fail** every time.

**Normal flow:**
1. Query ChromaDB for the expected decoder by `decoder_name`
2. Extract its `extracted_fields` from metadata
3. Inject the decoder into the LLM context

**Bootstrap Mode** (when no suitable decoder exists):

The pipeline detects when a Sigma rule maps to a **completely new log source** (unknown decoder, no relevant parent rules, zero-field decoder). In this case, it enters **Bootstrap Mode**:

```
┌─────────────────────────────────────────────┐
│           BOOTSTRAP MODE TRIGGERED           │
│  Reason: unknown decoder + no valid parents  │
│         OR decoder has ZERO fields           │
└─────────────────────────────────────────────┘
              │
              ▼
     ┌─────────────────────────┐
     │  GENERATE DECODER XML   │
     │  (Gemini 3.5 Flash)     │
     │  • Needs all Sigma fields│
     │  • <prematch> for ID     │
     │  • <regex>/<order> extr. │
     └────────┬────────────────┘
              │
              ▼
     ┌─────────────────────────┐
     │ VALIDATE DECODER FIELDS │
     │ • Check field coverage   │
     │ • Map Sigma → Wazuh      │
     │ • Ensure prematch exists │
     └────────┬────────────────┘
              │ PASS
              ▼
     ┌─────────────────────────┐
     │ GENERATE PARENT RULE    │
     │ • Unique ID (hash-based)│
     │ • level=0 grouping rule │
     │ • <decoded_as> link     │
     └────────┬────────────────┘
              │
              ▼
     ┌─────────────────────────┐
     │ ADD TO IN-MEMORY STORE  │
     │ • Validator can resolve │
     │   generated parents/     │
     │   decoders in subsequent │
     │   validation checks      │
     └─────────────────────────┘
```

**Why Bootstrap Mode is powerful:**
- Handles Sigma rules for **new platforms** not yet in your Wazuh deployment
- Generates **complete decoder XML** with field extraction logic
- Creates **valid parent rules** with proper hierarchy
- Maps Sigma fields to Wazuh decoder fields automatically
- Falls back to `syslog` decoder if generation fails

---

### Stage 6: LLM Generation

The **Gemini 3.5 Flash** model receives a richly structured prompt containing:

| Component | Purpose |
|-----------|---------|
| **Original Sigma rule** | The source of truth for detection logic |
| **SigWaz draft XML** | Baseline translation to improve upon |
| **Retrieved Wazuh rules** (k=5) | Real examples of how your org writes rules |
| **Parent rules** | Hierarchy context for `<if_sid>` |
| **Decoder XML** | Field extraction capabilities |
| **Bootstrap context** | Generated decoder + parent + field mappings (if applicable) |
| **Previous validation errors** | Feedback for iterative refinement |

**Prompt constraints enforced:**
- Wrap in `<group name="...">` — never bare `<rule>`
- Static fields use dedicated tags: `<url>`, `<srcip>`, `<dstip>`, `<user>`, `<id>`, `<protocol>`, `<action>`, `<status>`
- `<srcip>`/`<dstip>` are for literal IPs only
- No `<field name="full_log">` for log type context
- Single-line regex only
- Same-field tags = AND logic — use `|` for OR
- Only use fields the decoder extracts
- `type="pcre2"` required for regex metacharacters
- `<if_sid>` MUST exist in parents_context

---

### Stage 7: Validator Agent & Iterative Refinement

The **Validator Agent** is the quality gate. It performs 4 critical checks:

#### Check 1: XML Syntax Validation
```python
try:
    ET.fromstring(xml_string)
    return True, None
except ET.ParseError as e:
    return False, f"XML syntax error: {e}"
```

#### Check 2: Parent Rule Validation (`<if_sid>`)
- Does the parent rule exist in the knowledge base (or in-memory store)?
- Does the parent's platform match the rule's platform?
- Is the parent a valid grouping rule (`level <= 2` or `has_children=True`)?
- **Auto-suggests** valid alternative parents if the current one is invalid

#### Check 3: Decoder Field Validation
- Does the decoder exist in the knowledge base (or in-memory store)?
- Are all `<field name="...">` tags referencing fields that the decoder actually extracts?
- **Enforces static field tags**: `url`, `srcip`, `dstip`, `user`, `id`, `protocol`, `action`, `status` must use dedicated tags, not `<field name="...">`
- Catches silent failures before deployment

#### Check 4: New Rule Type Detection
- Detects when a Sigma rule maps to an entirely unknown log source
- Triggers Bootstrap Mode automatically
- Provides detailed reasoning (`unknown_decoder_no_parents`, `no_relevant_rules_for_category`)

#### Iterative Refinement Loop

```
Attempt 1/3 → Validator → FAIL → Reviews added to prompt
     ↑                              ↓
Attempt 2/3 ← LLM ←────────────────┘
     ↑
Attempt 3/3 → Validator → PASS → Done ✅
                          FAIL → Best effort output
```

**Max iterations:** 3 (configurable via `MAX_ITERATIONS`)

---

## Why Each Component Matters

### Why RAG? Why not just prompt an LLM?

LLMs hallucinate vendor-specific syntax and field names. By retrieving **real, working Wazuh rules** from your own environment, the model has concrete, trusted examples to imitate. This dramatically reduces hallucination and ensures the output matches your actual Wazuh deployment style and version.

### Why Parent Rules?

Wazuh rules are inherently hierarchical. Without proper parent resolution:
- Child rules **never trigger**
- The Wazuh manager may **fail to load** the ruleset
- Rule grouping and correlation break

Our pipeline automatically resolves `<if_sid>` references and includes the full parent rule in the LLM prompt, forcing the model to respect the existing hierarchy.

### Why Decoders?

Decoders are Wazuh's log parsers. If a rule checks for `fieldX` but the decoder doesn't extract `fieldX`, the rule **silently fails** every time. By indexing all decoders and injecting the relevant ones into the LLM context, we allow the model to verify field compatibility.

### Why Bootstrap Mode?

Most Sigma-to-Wazuh converters fail when encountering new log sources. Our pipeline **generates decoders and parent rules on-the-fly**, enabling conversion for platforms not yet in your Wazuh deployment.

### Why the Validator Agent?

One-shot generation produces errors that are only caught at deployment time. The Validator Agent:
- Catches **XML syntax errors** immediately
- Validates **parent rule existence and compatibility**
- Ensures **decoder field coverage**
- Enforces **Wazuh best practices** (static field tags, proper hierarchy)
- Provides **actionable feedback** for iterative refinement

### Why the Logger System?

The pipeline includes a **dual-output logger** that provides:
- **Colored console output** with timestamps for real-time monitoring
- **Persistent file logging** (`logs/ingestion.log`, `logs/retrieval.log`, `logs/validator.log`) for debugging and auditing
- **Structured log levels** (DEBUG, INFO, WARNING, ERROR, CRITICAL) for filtering
- **Per-module logging** (ingestion, retrieval, validator) for traceability

```
[16:24:32.145] [INFO    ] [ingestion   ] Embedding model loaded successfully
[16:24:32.146] [INFO    ] [ingestion   ] Loaded 1,247 XML files
[16:24:32.147] [WARNING ] [retrieval   ] Decoder 'apache-accesslog' has ZERO fields
[16:24:32.148] [ERROR   ] [validator   ] Parent 5715 is not a valid grouping rule (level=3)
```

---

## Project Structure

```
WAZUH-RAG/
│
├── data/
│   ├── decoders/                    # Wazuh decoder XML files (your log parsers)
│   │   ├── 0005-wazuh_decoders.xml
│   │   ├── 0025-apache_decoders.xml
│   │   └── ...
│   │
│   └── rules/                       # Wazuh rule XML files (your knowledge base)
│       ├── 0010-rules_config.xml
│       ├── 0020-syslog_rules.xml
│       ├── 0210-ids_rules.xml
│       └── ...
│
├── db/
│   └── wazuh-knowledge-base/        # Persistent ChromaDB vector store
│       ├── chroma.sqlite3
│       └── ...
│
├── logs/                            # Persistent log files (auto-created)
│   ├── ingestion.log
│   ├── retrieval.log
│   └── validator.log
│
├── scripts/                         # Core pipeline scripts
│   ├── __init__.py
│   ├── ingestion.py                 # Stage 1: Build knowledge base
│   ├── retrieval.py                 # Stage 2: Convert Sigma → Wazuh
│   ├── validator.py                 # Validator Agent
│   ├── logger.py                    # Shared logging configuration
│   └── utils.py                     # Shared utilities (ChromaDB filter builder)
│
├── sigwaz-cli/                      # SigWaz CLI tool (external dependency)
│   ├── sigwaz.py                    # Sigma-to-Wazuh converter
│   └── ...                          # (Cloned from public GitHub repository)
│
├── .env                             # Environment variables (API keys)
├── .gitignore
├── Improvements.txt                 # Development notes & TODOs
├── note.txt                         # Additional notes
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

---

## Prerequisites

- **Python 3.10+**
- **[SigWaz CLI](https://github.com/...)**: Must be cloned/installed in `sigwaz-cli/` (see Installation)
- **Wazuh rule files** (`*.xml`) placed in `data/rules/`
- **Wazuh decoder files** (`*.xml`) placed in `data/decoders/`
- **Google GenAI API key**: Required for Gemini 3.5 Flash

---

## Installation

```bash
# 1. Clone the Wazuh-RAG repository
git clone <your-repo-url>
cd WAZUH-RAG

# 2. Clone the SigWaz CLI tool (external dependency)
#    SigWaz is an open-source Sigma-to-Wazuh converter.
#    Clone it into the sigwaz-cli/ directory:
git clone https://github.com/<sigwaz-repo>/sigwaz-cli.git sigwaz-cli/

# 3. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Configure environment variables
cp .env.example .env
# Edit .env and add your GENAI_API_KEY
```

### Environment Variables (`.env`)

```env
GENAI_API_KEY=your_google_genai_api_key_here
```

---

## Usage

### Step 1: Ingest Your Wazuh Knowledge Base

Populate the vector database with your existing Wazuh rules and decoders:

```bash
cd scripts
python ingestion.py
```

**What happens:**
- Scans `data/rules/` and `data/decoders/` for `*.xml` files
- Extracts each `<rule>` and `<decoder>` block with metadata
- Embeds and stores them in `db/wazuh-knowledge-base/`

**Expected output:**
```
============================================================
WAZUH KNOWLEDGE BASE INGESTION STARTED
============================================================
[Step 1/4] Loading Wazuh rule files...
Loaded 247 XML files
[Step 2/4] Extracting individual rules...
Rule extraction complete:
  Total rules: 1,247
  Comments parsed: 89 (useful: 67, skipped: 22)
  Parent rules: 45
  Child rules: 1,202
  Platform distribution:
    linux: 523
    windows: 412
    web: 198
    unknown: 114
[Step 3/4] Loading Wazuh decoder files...
Found 34 decoder files
  Total decoders: 156
  Platform distribution:
    linux: 67
    windows: 45
    web: 28
    unknown: 16
[Step 4/4] Embedding into ChromaDB...
  Documents to embed: 1,403
    Rules: 1,247
    Decoders: 156
Starting embedding (this may take a few minutes)...
Embedding complete!
============================================================
INGESTION COMPLETE
============================================================
```

> **Note:** Run this whenever you update your Wazuh ruleset to keep the knowledge base current.

---

### Step 2: Convert a Sigma Rule

Edit `scripts/retrieval.py` and set the `yaml_rule` variable to your Sigma rule, then run:

```bash
python retrieval.py
```

**Example Sigma rule:**
```yaml
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
```

**What happens:**
1. Converts your Sigma YAML to draft Wazuh XML via SigWaz
2. Classifies the rule (platform=linux, category=process_creation)
3. Retrieves the 5 most semantically similar existing Linux Wazuh rules
4. Resolves parent rules via `<if_sid>` and validates them
5. Resolves decoders — enters Bootstrap Mode if needed
6. Generates the final Wazuh XML rule via Gemini
7. Validates output — iterates up to 3 times if errors found

**Sample output:**
```
============================================================
DECODER & PARENT RESOLUTION
============================================================
Decoder name:     linux_process_creation
Decoder source:   GENERATED (new)
Parent rule ID:   9LIN001
Parent source:    GENERATED
Field mapping:    {'Image': 'command', 'CommandLine': 'full_command'}
Bootstrap mode:   True
============================================================
--- Attempt 1/3 ---
XML extracted: 1,247 chars
  Rule if_sid: 9LIN001
VALIDATION PASSED
============================================================
FINAL OUTPUT SUMMARY
============================================================
Decoder:          linux_process_creation
Decoder source:   GENERATED
Parent ID:        9LIN001
Parent source:    GENERATED
Rule if_sid:      9LIN001
Rule uses fields: True
Validation:       PASSED
============================================================
RULE XML:
<group name="linux,process_creation">
  <rule id="100001" level="8">
    <if_sid>9LIN001</if_sid>
    <decoded_as>linux_process_creation</decoded_as>
    <field name="command">^.*(kill|killall|pkill|xkill)$</field>
    <description>Linux process termination command detected</description>
  </rule>
</group>
```

---

## The Validator Agent Deep Dive

The `ValidatorAgent` class (`scripts/validator.py`) is the pipeline's quality assurance layer.

### Validation Checks

| Check | Method | What it catches |
|-------|--------|---------------|
| **XML Syntax** | `_validate_xml_syntax()` | Malformed XML, unclosed tags, invalid characters |
| **Parent Existence** | `_validate_if_sid()` | References to non-existent parent rules |
| **Parent Platform Match** | `_validate_if_sid()` | Cross-platform parent-child mismatches |
| **Parent Grouping Validity** | `_validate_if_sid()` | Using non-grouping rules as parents |
| **Decoder Existence** | `_validate_decoder_fields()` | References to non-existent decoders |
| **Field Extraction** | `_validate_decoder_fields()` | Rules checking fields the decoder doesn't extract |
| **Static Field Enforcement** | `_validate_decoder_fields()` | Using `<field name="url">` instead of `<url>` |

### In-Memory Stores

The Validator Agent maintains two in-memory dictionaries for bootstrap mode:
- **`_in_memory_parents`**: Stores generated parent rules for validation during the same session
- **`_in_memory_decoders`**: Stores generated decoders for field validation during the same session

This allows the validator to resolve generated artifacts without persisting them to ChromaDB.

### Decoder Validation

When generating a new decoder in Bootstrap Mode, the validator checks:
1. **XML syntax** of the generated decoder
2. **Prematch requirement**: Decoder must have `<prematch>` or `<program_name>` for log identification
3. **Field coverage**: All Sigma fields must be extractable by the decoder
4. **Field mapping**: Maps Sigma field names to Wazuh decoder field names

---

## The Logger System

The `setup_logger()` function (`scripts/logger.py`) provides production-grade logging:

### Features

| Feature | Value |
|---------|-------|
| **Colored console output** | Real-time monitoring with color-coded log levels |
| **Persistent file logging** | Audit trail in `logs/{name}.log` |
| **Timestamp precision** | Millisecond-resolution timestamps |
| **Module isolation** | Separate log files per component (ingestion, retrieval, validator) |
| **Level filtering** | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| **Auto-directory creation** | Creates `logs/` directory automatically |

### Console Output Format
```
[16:24:32.145] [INFO    ] [ingestion   ] Embedding model loaded successfully
[16:24:32.146] [WARNING ] [retrieval   ] Decoder 'apache-accesslog' has ZERO fields
[16:24:32.147] [ERROR   ] [validator   ] XML syntax error: unclosed tag <rule>
```

### File Output Format
```
2026-07-22 16:24:32 | INFO     | ingestion    | Embedding model loaded successfully
2026-07-22 16:24:32 | WARNING  | retrieval    | Decoder 'apache-accesslog' has ZERO fields
2026-07-22 16:24:32 | ERROR    | validator    | XML syntax error: unclosed tag <rule>
```

---

## Customization

| Parameter | Location | Default | Description |
|-----------|----------|---------|-------------|
| `k` | `retrieval.py` → `retrieve_filtered()` | `5` | Number of similar rules to retrieve |
| `MAX_ITERATIONS` | `retrieval.py` | `3` | Maximum validation retry attempts |
| `model_name` | Both scripts | `all-MiniLM-L6-v2` | Sentence transformer for embeddings |
| `collection_name` | Both scripts | `wazuh_knowledge_base` | Chroma collection identifier |
| `persist_directory` | Both scripts | `db/wazuh-knowledge-base` | Where the vector DB is stored |
| `EMBEDDING_BATCH_SIZE` | Both scripts | `32` | Batch size for embedding generation |
| `SIMILARITY_SPACE` | Both scripts | `cosine` | Vector similarity metric |

---

## Requirements

See [`requirements.txt`](requirements.txt) for the full dependency list.

### Core Dependencies

| Package | Purpose |
|---------|---------|
| **langchain-core** | Document abstractions and core interfaces |
| **langchain-community** | Community integrations (TextLoader, DirectoryLoader) |
| **langchain-chroma** | ChromaDB vector store integration |
| **chromadb** | Local vector database for semantic search |
| **sentence-transformers** | Local embedding model (no OpenAI API needed) |
| **google-genai** | Gemini API client for rule generation |
| **python-dotenv** | Secure environment variable management |
| **PyYAML** | Sigma rule YAML parsing |

### External Dependencies

| Tool | Source | Purpose |
|------|--------|---------|
| **SigWaz CLI** | [GitHub](https://github.com/...) | Sigma-to-Wazuh baseline conversion |

---

## License

MIT
