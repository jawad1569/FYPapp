"""
build_vectorstore.py — RAG Vector Store Builder
Chunks knowledge base documents and embeds them into ChromaDB.
Run once (or whenever knowledge docs change):
    python build_vectorstore.py
"""

import os
import re
import chromadb
from chromadb.utils import embedding_functions

# ── Config ──
KNOWLEDGE_DIR = os.path.join(os.path.dirname(__file__), "knowledge")
CHROMA_DIR    = os.path.join(os.path.dirname(__file__), "vectorstore")
COLLECTION    = "wazuh_knowledge"
CHUNK_SIZE    = 800   # characters per chunk
CHUNK_OVERLAP = 150   # overlap between chunks


def chunk_markdown(text: str, source: str) -> list[dict]:
    """Split a markdown document into chunks by heading sections,
    then further split large sections by CHUNK_SIZE."""
    # Split on markdown headings (## or ###)
    sections = re.split(r'\n(?=#{1,3} )', text)
    chunks = []

    for section in sections:
        section = section.strip()
        if not section:
            continue

        # Extract heading for metadata
        heading_match = re.match(r'^(#{1,3})\s+(.+)', section)
        heading = heading_match.group(2) if heading_match else "General"

        # If section is small enough, keep as single chunk
        if len(section) <= CHUNK_SIZE:
            chunks.append({
                "text": section,
                "source": source,
                "heading": heading,
            })
        else:
            # Split into overlapping sub-chunks
            words = section.split()
            current_chunk = []
            current_len = 0

            for word in words:
                current_chunk.append(word)
                current_len += len(word) + 1

                if current_len >= CHUNK_SIZE:
                    chunk_text = " ".join(current_chunk)
                    chunks.append({
                        "text": chunk_text,
                        "source": source,
                        "heading": heading,
                    })
                    # Keep overlap
                    overlap_words = current_chunk[-CHUNK_OVERLAP // 5:]
                    current_chunk = list(overlap_words)
                    current_len = sum(len(w) + 1 for w in current_chunk)

            # Remaining text
            if current_chunk:
                chunk_text = " ".join(current_chunk)
                if len(chunk_text.strip()) > 50:
                    chunks.append({
                        "text": chunk_text,
                        "source": source,
                        "heading": heading,
                    })

    return chunks


def build():
    """Read all .md files in knowledge/, chunk them, and insert into ChromaDB."""
    print(f"[DIR] Knowledge dir: {os.path.abspath(KNOWLEDGE_DIR)}")
    print(f"[DB]  Vector store:  {os.path.abspath(CHROMA_DIR)}")

    # Collect all chunks
    all_chunks = []
    for filename in sorted(os.listdir(KNOWLEDGE_DIR)):
        if not filename.endswith(".md"):
            continue
        filepath = os.path.join(KNOWLEDGE_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()

        chunks = chunk_markdown(text, source=filename)
        all_chunks.extend(chunks)
        print(f"  [+] {filename}: {len(chunks)} chunks")

    if not all_chunks:
        print("[ERROR] No markdown files found in knowledge/")
        return

    # Create ChromaDB client with persistent storage
    client = chromadb.PersistentClient(path=CHROMA_DIR)

    # Use a small, fast embedding model (runs locally, ~80MB)
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    # Delete existing collection if it exists (rebuild from scratch)
    try:
        client.delete_collection(COLLECTION)
        print("  [*] Deleted old collection")
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION,
        embedding_function=embed_fn,
        metadata={"description": "WazuhBot RAG knowledge base"},
    )

    # Insert all chunks
    ids       = [f"chunk-{i}" for i in range(len(all_chunks))]
    documents = [c["text"] for c in all_chunks]
    metadatas = [{"source": c["source"], "heading": c["heading"]} for c in all_chunks]

    collection.add(ids=ids, documents=documents, metadatas=metadatas)

    print(f"\n[OK] Built vector store with {len(all_chunks)} chunks")
    print(f"     Collection: {COLLECTION}")
    print(f"     Stored at:  {os.path.abspath(CHROMA_DIR)}")


if __name__ == "__main__":
    build()
