from dotenv import load_dotenv
from langchain_community.document_loaders import TextLoader, DirectoryLoader
import os
from langchain_core.documents import Document
from langchain_text_splitters import CharacterTextSplitter # split text into chunks
from langchain_openai import OpenAIEmbeddings # generate embeddings using OpenAI's API
from langchain_chroma import Chroma # vector store for storing and querying embeddings
from langchain_community.embeddings import HuggingFaceEmbeddings
import re

load_dotenv()
GENAI_API_KEY = os.getenv("GENAI_API_KEY")

embedding_model = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"batch_size": 32}
)


def load_files(directory_path):

    """
    Load text files from a directory and return a list of documents.
    """
    loader = DirectoryLoader(
        directory_path,
        glob="*.xml", 
        loader_cls=lambda path: TextLoader(path, encoding="utf-8")
        )
    documents = loader.load()

    if len(documents) == 0:
        raise ValueError(f"No text files found in the directory: {directory_path}")
    
    for i , doc in enumerate(documents[:2]) : 
        print(f"""\ndocument {i+1} : \n 
              Source : {doc.metadata['source']} \n 
              Content length : {len(doc.page_content)} chars \n 
              Content preview : {doc.page_content[:50]}... \n 
              Metadata : {doc.metadata} \n """)
 
    return documents

def chunking(documents):
    """
    Extract Wazuh rules and attach the last useful XML comment
    as category metadata.

    Returns:
        List[Document]
    """

    rules_documents = []

    # Match comments and complete rule blocks in original order
    pattern = r"(<!--.*?-->|<rule\b.*?</rule>)"

    ignored_words = [
        "Copyright",
        "Created by",
        "Wazuh, Inc",
        "GPL",
        "free software"
    ]

    for doc in documents:

        current_category = None

        elements = re.findall(
            pattern,
            doc.page_content,
            flags=re.DOTALL
        )

        for element in elements:

            # ==========================
            # Handle XML comments
            # ==========================
            if element.startswith("<!--"):

                comment = element.replace("<!--", "") \
                                 .replace("-->", "") \
                                 .strip()

                # Clean comment formatting
                comment_clean = " ".join(
                    line.strip()
                    for line in comment.splitlines()
                    if line.strip()
                )

                # Ignore empty comments
                if not comment_clean:
                    continue

                # Ignore long explanations/changelog comments
                if len(comment_clean) > 100:
                    continue

                # Ignore license/header comments
                if any(
                    word.lower() in comment_clean.lower()
                    for word in ignored_words
                ):
                    continue

                # Save category for following rules
                current_category = comment_clean

                continue


            # ==========================
            # Handle Wazuh rules
            # ==========================
            if element.startswith("<rule"):

                rule = element.strip()

                # Extract rule ID
                rule_id_match = re.search(
                    r'id="(\d+)"',
                    rule
                )

                rule_id = (
                    rule_id_match.group(1)
                    if rule_id_match
                    else "unknown"
                )

                rules_documents.append(
                    Document(
                        page_content=rule,
                        metadata={
                            "category": current_category or "unknown",
                            "rule_id": rule_id,
                            "source": doc.metadata.get("source", "unknown")
                        }
                    )
                )

    return rules_documents


def embedding(langchain_documents, persist_directory="db/chroma_db"):
    """
    Create a vector store from the document chunks and persist it to disk.
    """

    vector_store = Chroma.from_documents(
        documents=langchain_documents,
        embedding=embedding_model,
        persist_directory=persist_directory,
        collection_name="rules_collection",
        collection_metadata={"hnsw:space": "cosine"}
    )
    print (f"finished creating the vector store and persisting it to disk at {persist_directory}")
    return vector_store



def main() : 
    
    print("************************\n Starting the ingestion pipeline...\n************************")

    # 1. loading the files 
    print("****\n Loading files...\n****")
    documents = load_files("./data/rules")

    # 2 chuncking the files
    print("****\n Chunking files...\n****")
    rules_documents = chunking(documents)

    print(f"Extracted {len(rules_documents)} rules")

    for doc in rules_documents[:3]:
        print("\n---")
        print(doc.metadata)
        print(doc.page_content[:200])
        
    # 3 Embedding the chunks and storing them in a vector DB
    print("****\n Embedding files...\n****")
    vector_store= embedding(rules_documents)



if __name__ == "__main__":
    main()
