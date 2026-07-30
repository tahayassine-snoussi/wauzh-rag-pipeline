"""
Shared utilities, configuration, constants, and exceptions for the Sigma -> Wazuh pipeline.
"""
import os
import re
from dataclasses import dataclass
from functools import wraps
from time import sleep

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document
from groq import Groq

load_dotenv()

# =============================================================================
# Custom Exception Hierarchy
# =============================================================================

class PipelineError(Exception):
    """Base exception for the conversion pipeline."""
    pass

class DecoderResolutionError(PipelineError):
    """Raised when decoder resolution fails completely."""
    pass

class ParentRuleDiscoveryError(PipelineError):
    """Raised when parent rule discovery/generation fails."""
    pass

class FieldCollisionError(PipelineError):
    """Raised when field collision is detected in generated XML."""
    pass

class XMLExtractionError(PipelineError):
    """Raised when XML cannot be extracted from LLM output."""
    pass

class ValidationError(PipelineError):
    """Raised when validation fails after max iterations."""
    pass


# =============================================================================
# Centralized LLM / DB Configuration
# =============================================================================

@dataclass
class LLMConfig:
    model: str = "llama-3.3-70b-versatile"
    temperature: float = 0.0
    max_tokens: int = 4096
    timeout: int = 60


LLM_CONFIG = LLMConfig()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_CLIENT = Groq(api_key=GROQ_API_KEY)

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
DECODER_VARIANT_FETCH_K = 100


# =============================================================================
# Retry Decorator
# =============================================================================

def retry_on_error(max_retries=3, backoff=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        sleep(backoff ** attempt)
            raise last_exception
        return wrapper
    return decorator


# =============================================================================
# Classification Maps
# =============================================================================

PRODUCT_PLATFORM_MAP = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "m365": "microsoft365",
    "office365": "microsoft365",
    "okta": "okta",
    "github": "github",
    "kubernetes": "kubernetes",
    "google_workspace": "google_workspace",
    "onelogin": "onelogin",
    "cisco": "network",
    "paloalto": "network",
    "fortinet": "network",
    "zeek": "network",
    "opencanary": "network",
    "modsecurity": "web",
}

SERVICE_PLATFORM_MAP = {
    "sysmon": "windows",
    "security": "windows",
    "system": "windows",
    "application": "windows",
    "powershell": "windows",
    "powershell-classic": "windows",
    "wmi": "windows",
    "taskscheduler": "windows",
    "applocker": "windows",
    "dns-server": "windows",
    "driver-framework": "windows",
    "windefend": "windows",
    "bits-client": "windows",
    "auditd": "linux",
    "sshd": "linux",
    "ssh": "linux",
    "cron": "linux",
    "systemd": "linux",
    "clamav": "linux",
    "docker": "linux",
    "kubernetes-audit": "kubernetes",
    "modsecurity": "web",
    "apache": "web",
    "nginx": "web",
    "iis": "web",
    "cloudtrail": "aws",
    "guardduty": "aws",
    "vpcflow": "aws",
    "azuread": "azure",
    "azure.activitylogs": "azure",
    "azure.signinlogs": "azure",
    "gcp.audit": "gcp",
    "okta": "okta",
    "github-audit": "github",
}

CATEGORY_PLATFORM_MAP = {
    "webserver": "web",
    "firewall": "network",
    "proxy": "network",
    "dns": "network",
    "network_connection": "network",
    "antivirus": "endpoint",
}

SERVICE_DECODER_MAP = {
    "auditd": "auditd",
    "sysmon": "windows-sysmon",
    "security": "windows-security",
    "system": "windows-system",
    "application": "windows-application",
    "powershell": "windows-powershell",
    "powershell-classic": "windows-powershell-classic",
    "wmi": "windows-wmi",
    "taskscheduler": "windows-taskscheduler",
    "applocker": "windows-applocker",
    "dns-server": "windows-dns-server",
    "sshd": "sshd",
    "ssh": "sshd",
    "cron": "cron",
    "systemd": "systemd",
    "clamav": "clamav",
    "docker": "docker",
    "kubernetes-audit": "kubernetes-audit",
    "apache": "apache-accesslog",
    "nginx": "nginx-accesslog",
    "iis": "iis-accesslog",
    "modsecurity": "modsecurity",
    "cloudtrail": "aws-cloudtrail",
    "guardduty": "aws-guardduty",
    "vpcflow": "aws-vpcflow",
    "azuread": "azure-ad",
    "azure.activitylogs": "azure-activitylogs",
    "azure.signinlogs": "azure-signinlogs",
    "gcp.audit": "gcp-audit",
    "okta": "okta",
    "github-audit": "github-audit",
}

CATEGORY_DECODER_MAP = {
    "webserver": "web-accesslog",
    "firewall": "firewall-generic",
    "dns": "dns-generic",
    "proxy": "proxy-generic",
    "antivirus": "antivirus-generic",
    "process_creation": "auditd",
}


# =============================================================================
# Low-level Helpers
# =============================================================================

def _norm(value: str | None) -> str | None:
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def build_chroma_filter(filter_dict: dict) -> dict:
    """
    Build ChromaDB-compatible filter from simple key-value pairs.
    """
    if not filter_dict:
        return {}

    conditions = []
    for key, value in filter_dict.items():
        conditions.append({key: {"$eq": value}})

    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


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