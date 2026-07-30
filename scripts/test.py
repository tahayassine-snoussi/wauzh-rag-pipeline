from utils import build_chroma_filter
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

EMBEDDING_MODEL = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"batch_size": 32}
)

db = Chroma(
    persist_directory="db/wazuh-knowledge-base",
    embedding_function=EMBEDDING_MODEL,
    collection_metadata={"hnsw:space": "cosine"},
    collection_name="wazuh_knowledge_base"
)


collection = db._collection

result = collection.get(
    where={
        "$and": [
            {"type": {"$eq": "rule"}},
            {"id": {"$eq": 80700}}
        ]
    }
)

print(result)