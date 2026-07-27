"""
Wazuh Knowledge Base Ingestion Pipeline
=========================================

Ingests Wazuh rules and decoders from XML files into a single ChromaDB collection.

Usage:
    python ingestion.py

Logs:
    logs/ingestion.log  (persistent)
    Console output      (colored, real-time)

FIX (2026-07): Decoder ingestion previously stored only a flat
`parent_decoder` string per decoder, with no way to query "give me every
child of X" without either walking every decoder document at retrieval time
or falling back to embeddings. This meant the retrieval pipeline had no
reliable, metadata-only way to find e.g. `auditd-syscall` starting from
`auditd`.

This version adds an explicit decoder-hierarchy pass after all decoders are
extracted:
    - root_decoder      -> the top-level ancestor of a decoder (walks the
                           parent chain all the way up; a root decoder is its
                           own root)
    - is_child_decoder  -> True if the decoder declares a <parent>
    - decoder_depth      -> distance from the root (0 for root decoders,
                           1 for direct children, 2 for grandchildren, etc.)

A parent -> children map is also built and logged, purely for
visibility/debugging; the metadata fields above are what retrieval actually
queries against.
"""

from dotenv import load_dotenv
from langchain_community.document_loaders import TextLoader, DirectoryLoader
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
import os
import re
from glob import glob
from collections import Counter

from logger import setup_logger

load_dotenv()

# ---------------------------------------------------------------------------
# Setup logger
# ---------------------------------------------------------------------------
logger = setup_logger("ingestion", level="INFO")

# ---------------------------------------------------------------------------
# Embedding model
# ---------------------------------------------------------------------------
logger.info("Initializing embedding model (all-MiniLM-L6-v2)")
EMBEDDING_MODEL = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"batch_size": 32}
)
logger.info("Embedding model loaded successfully")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IGNORED_COMMENT_WORDS = [
    "Copyright", "Created by", "Wazuh, Inc", "GPL", "free software",
    "License", "All rights reserved",
]

MAX_COMMENT_LENGTH = 100

PLATFORM_KEYWORDS = {
    "web": ["web", "apache", "nginx", "iis", "accesslog", "http", "squid"],
    "windows": ["windows", "sysmon", "security", "powershell", "msoffice", "win"],
    "linux": ["linux", "audit", "ssh", "sudo", "pam", "syslog", "auth"],
}

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
# Helpers
# ---------------------------------------------------------------------------

def is_useful_comment(comment: str) -> bool:
    """Check if an XML comment is a useful category label."""
    if not comment or not comment.strip():
        return False
    cleaned = " ".join(line.strip() for line in comment.splitlines() if line.strip())
    if len(cleaned) > MAX_COMMENT_LENGTH:
        return False
    if any(word.lower() in cleaned.lower() for word in IGNORED_COMMENT_WORDS):
        return False
    return True


def derive_platform(source_path: str, category: str, decoder_name: str = None) -> str:
    """Derive platform from source path, category, or decoder name."""
    combined = f"{source_path} {category} {decoder_name or ''}".lower()
    for platform, keywords in PLATFORM_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            logger.debug(f"Platform '{platform}' matched for: {source_path[:50]}...")
            return platform
    logger.debug(f"No platform match for: {source_path[:50]}...")
    return "unknown"


def map_to_logsource(platform: str, decoder_name: str, category: str) -> str:
    """Map Wazuh attributes to Sigma logsource.category."""
    combined = f"{decoder_name or ''} {category}".lower()
    for logsource, (plat, dec) in LOGSOURCE_DECODER_MAP.items():
        if dec.lower() in combined:
            return logsource
    if "web" in combined or "http" in combined or "access" in combined:
        return "webserver"
    elif "sysmon" in combined:
        return "sysmon"
    elif "windows" in combined or "win" in combined:
        return "windows"
    elif "linux" in combined or "audit" in combined or "ssh" in combined:
        return "linux"
    return "unknown"


def extract_rule_id(rule_xml: str) -> str:
    match = re.search(r'id="(\d+)"', rule_xml)
    return match.group(1) if match else "unknown"


def extract_parent_id(rule_xml: str) -> str | None:
    match = re.search(r'<if_sid>(\d+)</if_sid>', rule_xml)
    return match.group(1) if match else None


def extract_decoder_name(rule_xml: str) -> str | None:
    match = re.search(r'<decoded_as>([^<]+)</decoded_as>', rule_xml)
    return match.group(1).strip() if match else None


def extract_rule_level(rule_xml: str) -> str | None:
    match = re.search(r'level="(\d+)"', rule_xml)
    return match.group(1) if match else None


def extract_mitre_ids(rule_xml: str) -> list[str]:
    return re.findall(r'<id>(T\d+)</id>', rule_xml)


def extract_decoder_name_from_decoder(decoder_xml: str) -> str:
    match = re.search(r'<decoder\s+name="([^"]+)"', decoder_xml)
    return match.group(1) if match else "unknown"


def extract_parent_decoder(decoder_xml: str) -> str | None:
    match = re.search(r'<parent>([^<]+)</parent>', decoder_xml)
    return match.group(1).strip() if match else None


def extract_decoder_type(decoder_xml: str) -> str | None:
    match = re.search(r'<type>([^<]+)</type>', decoder_xml)
    return match.group(1).strip() if match else None


def extract_extracted_fields(decoder_xml: str) -> list[str]:
    fields = []
    for match in re.findall(r'<order>([^<]+)</order>', decoder_xml):
        fields.extend([f.strip() for f in match.split(",") if f.strip()])
    return fields


def clean_metadata_for_chroma(metadata: dict) -> dict:
    """
    ChromaDB does not accept empty lists in metadata.
    Convert empty lists to None (which ChromaDB omits).
    """
    cleaned = {}
    for key, value in metadata.items():
        if isinstance(value, list) and len(value) == 0:
            cleaned[key] = None
        else:
            cleaned[key] = value
    return cleaned


# ---------------------------------------------------------------------------
# Decoder hierarchy processing
# ---------------------------------------------------------------------------

def compute_decoder_hierarchy(decoder_documents: list[Document]) -> dict[str, list[str]]:
    """
    Walk every decoder's <parent> chain to compute:
        - root_decoder     : top-level ancestor (a root decoder is its own root)
        - is_child_decoder : True if this decoder declares a <parent>
        - decoder_depth     : distance from the root (0, 1, 2, ...)

    Mutates each Document's metadata in place, and returns a parent -> children
    name map for logging/debugging.

    This is what lets retrieval answer "find all children of auditd" purely
    from metadata filters, with no dependency on embeddings.
    """
    name_to_doc = {d.metadata["decoder_name"]: d for d in decoder_documents}
    parent_to_children: dict[str, list[str]] = {}

    for doc in decoder_documents:
        name = doc.metadata["decoder_name"]
        parent = doc.metadata.get("parent_decoder")
        if parent:
            parent_to_children.setdefault(parent, []).append(name)

    def resolve_root_and_depth(name: str, seen: frozenset) -> tuple[str, int]:
        doc = name_to_doc.get(name)
        if doc is None:
            # Parent referenced but not present in this ingestion batch —
            # treat the referenced name itself as the root.
            return name, 0
        parent = doc.metadata.get("parent_decoder")
        if not parent or parent == name or parent in seen:
            # No parent, self-reference, or a cycle -> stop here, this is root.
            return name, 0
        root, depth = resolve_root_and_depth(parent, seen | {name})
        return root, depth + 1

    for doc in decoder_documents:
        name = doc.metadata["decoder_name"]
        parent = doc.metadata.get("parent_decoder")
        root, depth = resolve_root_and_depth(name, frozenset())
        doc.metadata["root_decoder"] = root
        doc.metadata["is_child_decoder"] = bool(parent)
        doc.metadata["decoder_depth"] = depth

    logger.info("Decoder hierarchy (parent -> children):")
    if parent_to_children:
        for parent, children in sorted(parent_to_children.items()):
            logger.info(f"  {parent}: {children}")
    else:
        logger.info("  (no parent/child relationships found)")

    return parent_to_children


# ---------------------------------------------------------------------------
# File Loading
# ---------------------------------------------------------------------------

def load_files(directory_path: str) -> list[Document]:
    """Load XML files from a directory."""
    logger.info(f"Loading XML files from: {directory_path}")

    loader = DirectoryLoader(
        directory_path,
        glob="*.xml",
        loader_cls=lambda path: TextLoader(path, encoding="utf-8")
    )
    documents = loader.load()

    if len(documents) == 0:
        logger.error(f"No XML files found in: {directory_path}")
        raise ValueError(f"No XML files found in: {directory_path}")

    logger.info(f"Loaded {len(documents)} XML files")

    for i, doc in enumerate(documents[:3]):
        logger.debug(f"File {i+1}: {doc.metadata.get('source')} ({len(doc.page_content)} chars)")

    return documents


# ---------------------------------------------------------------------------
# Rule Chunking
# ---------------------------------------------------------------------------

def chunk_rules(documents: list[Document]) -> list[Document]:
    """Extract individual Wazuh <rule> blocks from XML files."""
    logger.info("Starting rule extraction...")
    rules_documents = []
    pattern = r"(<!--.*?-->|<rule\b.*?</rule>)"

    total_comments = 0
    useful_comments = 0
    skipped_comments = 0

    for doc in documents:
        current_category = None
        source_path = doc.metadata.get("source", "unknown")
        elements = re.findall(pattern, doc.page_content, flags=re.DOTALL)

        for element in elements:
            if element.startswith("<!--"):
                total_comments += 1
                comment = element.replace("<!--", "").replace("-->", "").strip()
                cleaned = " ".join(line.strip() for line in comment.splitlines() if line.strip())
                if is_useful_comment(cleaned):
                    useful_comments += 1
                    current_category = cleaned
                else:
                    skipped_comments += 1
                continue

            if element.startswith("<rule"):
                rule_xml = element.strip()
                rule_id = extract_rule_id(rule_xml)
                parent_id = extract_parent_id(rule_xml)
                decoder_name = extract_decoder_name(rule_xml)
                level = extract_rule_level(rule_xml)
                mitre_ids = extract_mitre_ids(rule_xml)
                platform = derive_platform(source_path, current_category, decoder_name)
                logsource = map_to_logsource(platform, decoder_name, current_category or "")

                metadata = {
                    "type": "rule",
                    "rule_id": rule_id,
                    "category": current_category or "unknown",
                    "parent_rule_id": parent_id,
                    "decoder_name": decoder_name,
                    "rule_level": level,
                    "platform": platform,
                    "logsource_category": logsource,
                    "mitre_ids": mitre_ids,
                    "has_children": False,
                    "source": source_path,
                }
                # Fix: ChromaDB rejects empty lists
                metadata = clean_metadata_for_chroma(metadata)

                rules_documents.append(Document(
                    page_content=rule_xml,
                    metadata=metadata
                ))

    # Post-process: mark parents
    all_rule_ids = {d.metadata["rule_id"] for d in rules_documents}
    parent_ids = set()
    for d in rules_documents:
        pid = d.metadata.get("parent_rule_id")
        if pid and pid in all_rule_ids:
            parent_ids.add(pid)
    for d in rules_documents:
        if d.metadata["rule_id"] in parent_ids:
            d.metadata["has_children"] = True

    # Stats
    parents_count = len(parent_ids)

    logger.info(f"Rule extraction complete:")
    logger.info(f"  Total rules: {len(rules_documents)}")
    logger.info(f"  Comments parsed: {total_comments} (useful: {useful_comments}, skipped: {skipped_comments})")
    logger.info(f"  Parent rules: {parents_count}")
    logger.info(f"  Child rules: {len(rules_documents) - parents_count}")
    logger.info(f"  Platform distribution:")

    platforms = Counter(d.metadata["platform"] for d in rules_documents)
    for plat, count in platforms.most_common():
        logger.info(f"    {plat}: {count}")

    return rules_documents


# ---------------------------------------------------------------------------
# Decoder Chunking
# ---------------------------------------------------------------------------

def chunk_decoders(decoder_directory: str = "data/decoders") -> list[Document]:
    """Extract individual Wazuh <decoder> blocks from decoder XML files."""
    logger.info(f"Loading decoders from: {decoder_directory}")
    decoder_documents = []
    pattern = r"(<!--.*?-->|<decoder\b.*?</decoder>)"

    files = glob(os.path.join(decoder_directory, "*.xml"))
    logger.info(f"Found {len(files)} decoder files")

    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            continue

        current_category = None
        elements = re.findall(pattern, content, flags=re.DOTALL)

        for element in elements:
            if element.startswith("<!--"):
                comment = element.replace("<!--", "").replace("-->", "").strip()
                cleaned = " ".join(line.strip() for line in comment.splitlines() if line.strip())
                if is_useful_comment(cleaned):
                    current_category = cleaned
                continue

            if element.startswith("<decoder"):
                decoder_xml = element.strip()
                name = extract_decoder_name_from_decoder(decoder_xml)
                parent = extract_parent_decoder(decoder_xml)
                dec_type = extract_decoder_type(decoder_xml)
                fields = extract_extracted_fields(decoder_xml)
                platform = derive_platform(file_path, current_category or "", name)

                metadata = {
                    "type": "decoder",
                    "decoder_name": name,
                    "parent_decoder": parent,
                    "decoder_type": dec_type or "syslog",
                    "platform": platform,
                    "extracted_fields": fields,
                    "category": current_category or "unknown",
                    "source_file": file_path,
                }
                # Fix: ChromaDB rejects empty lists
                metadata = clean_metadata_for_chroma(metadata)

                decoder_documents.append(Document(
                    page_content=decoder_xml,
                    metadata=metadata
                ))

    # ---- Parent hierarchy processing --------------------------------------
    # Populates root_decoder / is_child_decoder / decoder_depth on every
    # decoder document so retrieval can find "all children of X" from
    # metadata alone, without depending on embeddings.
    compute_decoder_hierarchy(decoder_documents)

    logger.info(f"Decoder extraction complete:")
    logger.info(f"  Total decoders: {len(decoder_documents)}")

    platforms = Counter(d.metadata["platform"] for d in decoder_documents)
    logger.info(f"  Platform distribution:")
    for plat, count in platforms.most_common():
        logger.info(f"    {plat}: {count}")

    root_count = sum(1 for d in decoder_documents if not d.metadata["is_child_decoder"])
    child_count = len(decoder_documents) - root_count
    logger.info(f"  Root decoders: {root_count}")
    logger.info(f"  Child decoders: {child_count}")

    with_fields = [(d.metadata["decoder_name"], len(d.metadata["extracted_fields"]))
                   for d in decoder_documents if d.metadata["extracted_fields"]]
    with_fields.sort(key=lambda x: x[1], reverse=True)
    logger.info(f"  Top decoders by extracted fields:")
    for name, count in with_fields[:5]:
        logger.info(f"    {name}: {count} fields")

    return decoder_documents


# ---------------------------------------------------------------------------
# Embedding
# ---------------------------------------------------------------------------

def create_vector_store(documents: list[Document], persist_directory: str = "db/wazuh-knowledge-base") -> Chroma:
    """Create a ChromaDB vector store from documents."""
    logger.info(f"Creating vector store at: {persist_directory}")
    logger.info(f"  Documents to embed: {len(documents)}")

    rule_count = sum(1 for d in documents if d.metadata.get("type") == "rule")
    decoder_count = sum(1 for d in documents if d.metadata.get("type") == "decoder")
    logger.info(f"    Rules: {rule_count}")
    logger.info(f"    Decoders: {decoder_count}")

    logger.info("Starting embedding (this may take a few minutes)...")

    try:
        vector_store = Chroma.from_documents(
            documents=documents,
            embedding=EMBEDDING_MODEL,
            persist_directory=persist_directory,
            collection_name="wazuh_knowledge_base",
            collection_metadata={"hnsw:space": "cosine"}
        )
        logger.info("Embedding complete!")
        logger.info(f"Vector store created: {persist_directory}")
        return vector_store
    except Exception as e:
        logger.error(f"Embedding failed: {e}")
        logger.error("This usually means:")
        logger.error("  - Empty lists in metadata (fixed in clean_metadata_for_chroma)")
        logger.error("  - Invalid metadata types (must be str, int, float, bool)")
        logger.error("  - Corrupt ChromaDB directory (try deleting db/ and re-running)")
        raise


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 60)
    logger.info("WAZUH KNOWLEDGE BASE INGESTION STARTED")
    logger.info("=" * 60)

    logger.info("[Step 1/4] Loading Wazuh rule files...")
    rule_files = load_files("./data/rules")

    logger.info("[Step 2/4] Extracting individual rules...")
    rules_docs = chunk_rules(rule_files)

    logger.info("[Step 3/4] Loading Wazuh decoder files...")
    decoder_docs = chunk_decoders("./data/decoders")

    logger.info("[Step 4/4] Embedding into ChromaDB...")
    all_docs = rules_docs + decoder_docs
    create_vector_store(all_docs)

    logger.info("=" * 60)
    logger.info("INGESTION COMPLETE")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()