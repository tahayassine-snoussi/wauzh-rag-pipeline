"""
Wazuh Knowledge Base Ingestion Pipeline
=========================================

This pipeline ingests Wazuh rules and decoders from XML files,
extracts rich metadata, and stores them in a single ChromaDB collection
for hybrid retrieval (semantic + metadata filtering).

Collections:
    - "wazuh_knowledge_base": Contains both rules and decoders
      separated by metadata field "type" ("rule" | "decoder")

Metadata Schema for Rules:
    - type: "rule"
    - rule_id: Wazuh rule ID (e.g., "31104")
    - category: Category from preceding XML comment (e.g., "Web attacks")
    - parent_rule_id: Parent rule ID from <if_sid> (e.g., "31100")
    - decoder_name: Decoder referenced in <decoded_as> (e.g., "web-accesslog")
    - rule_level: Alert level from level="X" (e.g., "5")
    - platform: Derived platform ("web" | "windows" | "linux" | "unknown")
    - logsource_category: Maps to Sigma logsource.category (e.g., "webserver")
    - mitre_ids: List of MITRE ATT&CK IDs (e.g., ["T1190"])
    - has_children: True if other rules reference this as parent
    - source: Source file path

Metadata Schema for Decoders:
    - type: "decoder"
    - decoder_name: Decoder name from <decoder name="...">
    - parent_decoder: Parent decoder from <parent> (if child decoder)
    - platform: Derived platform ("web" | "windows" | "linux" | "unknown")
    - extracted_fields: List of fields from <order> tags
    - source_file: Source file path
"""

from dotenv import load_dotenv
from langchain_community.document_loaders import TextLoader, DirectoryLoader
import os
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
import re
from glob import glob

load_dotenv()

# ---------------------------------------------------------------------------
# Embedding model
# ---------------------------------------------------------------------------
embedding_model = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"batch_size": 32}
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Words to ignore when parsing XML comments (license headers, etc.)
IGNORED_COMMENT_WORDS = [
    "Copyright",
    "Created by",
    "Wazuh, Inc",
    "GPL",
    "free software",
    "License",
    "All rights reserved",
]

# Maximum length for a useful comment (longer = changelog/explanation)
MAX_COMMENT_LENGTH = 100

# Platform detection keywords mapped from source paths and categories
PLATFORM_KEYWORDS = {
    "web": ["web", "apache", "nginx", "iis", "accesslog", "http", "squid"],
    "windows": ["windows", "sysmon", "security", "powershell", "msoffice", "win"],
    "linux": ["linux", "audit", "ssh", "sudo", "pam", "syslog", "auth"],
}

# Sigma logsource.category to Wazuh decoder/platform mapping
LOGSOURCE_DECODER_MAP = {
    "webserver": ("web", "web-accesslog"),
    "apache": ("web", "apache-accesslog"),
    "nginx": ("web", "nginx-accesslog"),
    "iis": ("web", "iis-accesslog"),
    "sysmon": ("windows", "windows-sysmon"),
    "security": ("windows", "windows-security"),
    "windows": ("windows", "windows-eventchannel"),
    "linux": ("linux", "linux-syslog"),
    "auditd": ("linux", "linux-audit"),
    "ssh": ("linux", "ssh-decoder"),
    "firewall": ("network", "firewall"),
}

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def is_useful_comment(comment: str) -> bool:
    """
    Determine if an XML comment is useful as a category label.

    Filters out:
        - Empty comments
        - License/copyright headers
        - Long changelog-style comments
        - Comments containing ignored words

    Args:
        comment: Raw comment text (without <!-- -->)

    Returns:
        True if comment should be used as category
    """
    if not comment or not comment.strip():
        return False

    # Clean and normalize
    cleaned = " ".join(line.strip() for line in comment.splitlines() if line.strip())

    if len(cleaned) > MAX_COMMENT_LENGTH:
        return False

    if any(word.lower() in cleaned.lower() for word in IGNORED_COMMENT_WORDS):
        return False

    return True

def derive_platform(source_path: str, category: str, decoder_name: str = None) -> str:
    """
    Derive the platform from source path, category, or decoder name.

    Priority:
        1. Source path keywords (e.g., "rules/web/..." -> web)
        2. Category keywords (e.g., "Web attacks" -> web)
        3. Decoder name keywords (e.g., "web-accesslog" -> web)

    Args:
        source_path: File path of the source XML
        category: Extracted category comment
        decoder_name: Decoder name if available

    Returns:
        Platform string: "web", "windows", "linux", or "unknown"
    """
    combined_text = f"{source_path} {category} {decoder_name or ''}".lower()

    for platform, keywords in PLATFORM_KEYWORDS.items():
        if any(kw in combined_text for kw in keywords):
            return platform

    return "unknown"

def map_to_logsource(platform: str, decoder_name: str, category: str) -> str:
    """
    Map Wazuh rule attributes to Sigma logsource.category.

    This helps the retrieval pipeline filter rules by Sigma logsource.

    Args:
        platform: Derived platform
        decoder_name: Decoder name from <decoded_as>
        category: Category comment

    Returns:
        Sigma logsource.category string (e.g., "webserver")
    """
    combined = f"{decoder_name or ''} {category}".lower()

    # Direct decoder name matches
    for logsource, (plat, dec) in LOGSOURCE_DECODER_MAP.items():
        if dec.lower() in combined:
            return logsource

    # Category-based fallback
    if "web" in combined or "http" in combined or "access" in combined:
        return "webserver"
    elif "sysmon" in combined:
        return "sysmon"
    elif "windows" in combined or "win" in combined:
        return "windows"
    elif "linux" in combined or "audit" in combined or "ssh" in combined:
        return "linux"

    return "unknown"

# ---------------------------------------------------------------------------
# XML Element Extraction Helpers
# ---------------------------------------------------------------------------
def extract_rule_id(rule_xml: str) -> str:
    """Extract rule ID from <rule id="..."> attribute."""
    match = re.search(r'id="(\d+)"', rule_xml)
    return match.group(1) if match else "unknown"

def extract_parent_id(rule_xml: str) -> str | None:
    """Extract parent rule ID from <if_sid> tag."""
    match = re.search(r'<if_sid>(\d+)</if_sid>', rule_xml)
    return match.group(1) if match else None

def extract_decoder_name(rule_xml: str) -> str | None:    
    """Extract decoder name from <decoded_as> tag."""
    match = re.search(r'<decoded_as>([^<]+)</decoded_as>', rule_xml)
    return match.group(1).strip() if match else None

def extract_rule_level(rule_xml: str) -> str | None:
    """Extract alert level from level="X" attribute."""
    match = re.search(r'level="(\d+)"', rule_xml)
    return match.group(1) if match else None

def extract_mitre_ids(rule_xml: str) -> list[str]:
    """Extract all MITRE ATT&CK IDs from <id>T...</id> tags."""
    return re.findall(r'<id>(T\d+)</id>', rule_xml)

def extract_decoder_name_from_decoder(decoder_xml: str) -> str:
    """Extract decoder name from <decoder name="..."> attribute."""
    match = re.search(r'<decoder\s+name="([^"]+)"', decoder_xml)
    return match.group(1) if match else "unknown"

def extract_parent_decoder(decoder_xml: str) -> str | None:
    """Extract parent decoder name from <parent> tag."""
    match = re.search(r'<parent>([^<]+)</parent>', decoder_xml)
    return match.group(1).strip() if match else None

def extract_decoder_type(decoder_xml: str) -> str | None:
    """Extract decoder type from <type> tag (syslog, web-log, firewall, etc.)."""
    match = re.search(r'<type>([^<]+)</type>', decoder_xml)
    return match.group(1).strip() if match else None

def extract_extracted_fields(decoder_xml: str) -> list[str]:
    """
    Extract field names from <order> tags in decoder XML.

    Example: <order>url, srcip, protocol</order> -> ["url", "srcip", "protocol"]

    Also extracts from <order> tags that appear in child decoders.
    """
    fields = []
    # Find all <order> tags and extract comma-separated field names
    order_matches = re.findall(r'<order>([^<]+)</order>', decoder_xml)
    for match in order_matches:
        fields.extend([f.strip() for f in match.split(",") if f.strip()])
    return fields


# ---------------------------------------------------------------------------
# File Loading
# ---------------------------------------------------------------------------
def load_files(directory_path: str) -> list[Document]:
    """
    Load XML files from a directory.

    Args:
        directory_path: Path to directory containing .xml files

    Returns:
        List of LangChain Document objects with raw XML content

    Raises:
        ValueError: If no XML files are found
    """
    loader = DirectoryLoader(
        directory_path,
        glob="*.xml",
        loader_cls=lambda path: TextLoader(path, encoding="utf-8")
    )
    documents = loader.load()

    if len(documents) == 0:
        raise ValueError(f"No XML files found in: {directory_path}")

    # Preview first 2 documents
    for i, doc in enumerate(documents[:2]):
        print(f"""
Document {i + 1}:
    Source: {doc.metadata.get('source', 'unknown')}
    Content length: {len(doc.page_content)} chars
    Content preview: {doc.page_content[:80]}...
    Metadata: {doc.metadata}
""")

    return documents


# ---------------------------------------------------------------------------
# Rule Chunking
# ---------------------------------------------------------------------------
def chunk_rules(documents: list[Document]) -> list[Document]:
    """
    Extract individual Wazuh <rule> blocks from XML files.

    Also extracts useful category comments that precede rules.
    Computes parent-child relationships (has_children flag).

    Args:
        documents: List of Document objects from load_files()

    Returns:
        List of Document objects, one per Wazuh rule, with rich metadata
    """
    rules_documents = []

    # Pattern to match XML comments and complete <rule> blocks
    element_pattern = r"(<!--.*?-->|<rule\b.*?</rule>)"

    for doc in documents:
        current_category = None
        source_path = doc.metadata.get("source", "unknown")

        elements = re.findall(element_pattern, doc.page_content, flags=re.DOTALL)

        for element in elements:
            # ---------------------------------------------------------------
            # Handle XML comments -> potential category labels
            # ---------------------------------------------------------------
            if element.startswith("<!--"):
                comment = element.replace("<!--", "").replace("-->", "").strip()
                comment_clean = " ".join(
                    line.strip() for line in comment.splitlines() if line.strip()
                )

                if is_useful_comment(comment_clean):
                    current_category = comment_clean

                continue

            # ---------------------------------------------------------------
            # Handle Wazuh rules
            # ---------------------------------------------------------------
            if element.startswith("<rule"):
                rule_xml = element.strip()

                # Extract all metadata from the rule XML
                rule_id = extract_rule_id(rule_xml)
                parent_id = extract_parent_id(rule_xml)
                decoder_name = extract_decoder_name(rule_xml)
                level = extract_rule_level(rule_xml)
                mitre_ids = extract_mitre_ids(rule_xml)

                # Derive platform and logsource mapping
                platform = derive_platform(source_path, current_category, decoder_name)
                logsource = map_to_logsource(platform, decoder_name, current_category or "")

                rules_documents.append(Document(
                    page_content=rule_xml,
                    metadata={
                        "type": "rule",
                        "rule_id": rule_id,
                        "category": current_category or "unknown",
                        "parent_rule_id": parent_id,
                        "decoder_name": decoder_name,
                        "rule_level": level,
                        "platform": platform,
                        "logsource_category": logsource,
                        "mitre_ids": mitre_ids,
                        "has_children": False,  # Computed in post-processing
                        "source": source_path,
                    }
                ))

    # ---------------------------------------------------------------
    # Post-processing: Mark rules that are parents of other rules
    # ---------------------------------------------------------------
    all_rule_ids = {doc.metadata["rule_id"] for doc in rules_documents}
    parent_ids = set()

    for doc in rules_documents:
        parent_id = doc.metadata.get("parent_rule_id")
        if parent_id and parent_id in all_rule_ids:
            parent_ids.add(parent_id)

    for doc in rules_documents:
        if doc.metadata["rule_id"] in parent_ids:
            doc.metadata["has_children"] = True

    return rules_documents


# ---------------------------------------------------------------------------
# Decoder Chunking
# ---------------------------------------------------------------------------
def chunk_decoders(decoder_directory: str = "data/decoders") -> list[Document]:
    """
    Extract individual Wazuh <decoder> blocks from decoder XML files.

    Also extracts useful category comments that precede decoders,
    similar to how rules are processed.

    Args:
        decoder_directory: Path to directory containing decoder .xml files

    Returns:
        List of Document objects, one per Wazuh decoder, with metadata
    """
    decoder_documents = []

    # Pattern to match XML comments and complete <decoder> blocks
    element_pattern = r"(<!--.*?-->|<decoder\b.*?</decoder>)"

    for file_path in glob(os.path.join(decoder_directory, "*.xml")):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"Warning: Failed to read {file_path}: {e}")
            continue

        current_category = None

        elements = re.findall(element_pattern, content, flags=re.DOTALL)

        for element in elements:
            # ---------------------------------------------------------------
            # Handle XML comments -> potential category labels for decoders
            # ---------------------------------------------------------------
            if element.startswith("<!--"):
                comment = element.replace("<!--", "").replace("-->", "").strip()
                comment_clean = " ".join(
                    line.strip() for line in comment.splitlines() if line.strip()
                )

                if is_useful_comment(comment_clean):
                    current_category = comment_clean

                continue

            # ---------------------------------------------------------------
            # Handle Wazuh decoders
            # ---------------------------------------------------------------
            if element.startswith("<decoder"):
                decoder_xml = element.strip()

                # Extract metadata from decoder XML
                name = extract_decoder_name_from_decoder(decoder_xml)
                parent = extract_parent_decoder(decoder_xml)
                dec_type = extract_decoder_type(decoder_xml)
                fields = extract_extracted_fields(decoder_xml)

                # Derive platform from decoder name and category
                platform = derive_platform(file_path, current_category or "", name)

                decoder_documents.append(Document(
                    page_content=decoder_xml,
                    metadata={
                        "type": "decoder",
                        "decoder_name": name,
                        "parent_decoder": parent,
                        "decoder_type": dec_type or "syslog",  # Default type is syslog
                        "platform": platform,
                        "extracted_fields": fields,
                        "category": current_category or "unknown",
                        "source_file": file_path,
                    }
                ))

    return decoder_documents


# ---------------------------------------------------------------------------
# Embedding & Storage
# ---------------------------------------------------------------------------
def create_vector_store(documents: list[Document], persist_directory: str = "db/wazuh-knowledge-base") -> Chroma:
    """
    Create a ChromaDB vector store from documents and persist to disk.

    Uses a single collection for both rules and decoders.
    Documents are distinguished by the "type" metadata field.

    Args:
        documents: List of Document objects (rules + decoders)
        persist_directory: Directory to persist the vector store

    Returns:
        Chroma vector store instance
    """
    vector_store = Chroma.from_documents(
        documents=documents,
        embedding=embedding_model,
        persist_directory=persist_directory,
        collection_name="wazuh_knowledge_base",
        collection_metadata={"hnsw:space": "cosine"}
    )
    print(f"Vector store created and persisted to: {persist_directory}")
    print(f"   Total documents: {len(documents)}")
    return vector_store


# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------
def main():
    """Run the complete ingestion pipeline."""

    print("=" * 60)
    print("WAZUH KNOWLEDGE BASE INGESTION PIPELINE")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: Load Wazuh rules
    # ------------------------------------------------------------------
    print("\n[Step 1] Loading Wazuh rule files...")
    rule_files = load_files("./data/rules")
    print(f"   Loaded {len(rule_files)} rule XML files")

    # ------------------------------------------------------------------
    # Step 2: Chunk rules into individual <rule> blocks
    # ------------------------------------------------------------------
    print("\n[Step 2] Extracting individual rules...")
    rules_docs = chunk_rules(rule_files)
    print(f"   Extracted {len(rules_docs)} rules")

    # Preview first 3 rules
    print("\n   Preview of first 3 rules:")
    for doc in rules_docs[:3]:
        print(f"   - Rule ID: {doc.metadata['rule_id']:<8} | "
              f"Level: {doc.metadata['rule_level'] or 'N/A':<3} | "
              f"Platform: {doc.metadata['platform']:<8} | "
              f"Category: {doc.metadata['category'][:40]}")
        print(f"     Parent: {doc.metadata['parent_rule_id'] or 'None':<8} | "
              f"Decoder: {doc.metadata['decoder_name'] or 'None':<20} | "
              f"MITRE: {doc.metadata['mitre_ids']}")
        print(f"     Has children: {doc.metadata['has_children']}")
        print(f"     Content preview: {doc.page_content[:120]}...")
        print()

    # ------------------------------------------------------------------
    # Step 3: Load Wazuh decoders
    # ------------------------------------------------------------------
    print("\n[Step 3] Loading Wazuh decoder files...")
    decoder_docs = chunk_decoders("./data/decoders")
    print(f"   Extracted {len(decoder_docs)} decoders")

    # Preview first 3 decoders
    if decoder_docs:
        print("\n   Preview of first 3 decoders:")
        for doc in decoder_docs[:3]:
            print(f"   - Decoder: {doc.metadata['decoder_name']:<25} | "
                  f"Platform: {doc.metadata['platform']:<8} | "
                  f"Type: {doc.metadata['decoder_type']}")
            print(f"     Parent: {doc.metadata['parent_decoder'] or 'None':<20} | "
                  f"Fields: {doc.metadata['extracted_fields']}")
            print(f"     Content preview: {doc.page_content[:120]}...")
            print()

    # ------------------------------------------------------------------
    # Step 4: Combine and embed
    # ------------------------------------------------------------------
    print("\n[Step 4] Embedding into ChromaDB...")
    all_docs = rules_docs + decoder_docs

    # Count by type
    rule_count = sum(1 for d in all_docs if d.metadata["type"] == "rule")
    decoder_count = sum(1 for d in all_docs if d.metadata["type"] == "decoder")
    print(f"   Rules: {rule_count}")
    print(f"   Decoders: {decoder_count}")
    print(f"   Total: {len(all_docs)}")

    vector_store = create_vector_store(all_docs)

    # ------------------------------------------------------------------
    # Step 5: Verification
    # ------------------------------------------------------------------
    print("\n[Done] Ingestion complete!")
    print(f"   Collection: wazuh_knowledge_base")
    print(f"   Location: db/wazuh-knowledge-base")
    print(f"\n   You can now query with filters like:")
    print('     filter={"type": "rule", "platform": "web"}')
    print('     filter={"type": "decoder", "decoder_name": "web-accesslog"}')
    print('     filter={"type": "rule", "has_children": True}')


if __name__ == "__main__":
    main()