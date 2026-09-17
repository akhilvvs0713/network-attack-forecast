import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer


BASE_DIR = Path(__file__).resolve().parents[1]

INPUT_FILE = BASE_DIR / "data" / "mitre_documents.jsonl"
OUTPUT_DIR = BASE_DIR / "data" / "embeddings"

EMBEDDINGS_FILE = OUTPUT_DIR / "embeddings.npy"
METADATA_FILE = OUTPUT_DIR / "metadata.json"

MODEL_NAME = "all-MiniLM-L6-v2"


def load_documents():
    documents = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                documents.append(json.loads(line))

    return documents


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading documents...")
    documents = load_documents()

    if not documents:
        raise RuntimeError("No MITRE documents found.")

    print(f"Documents: {len(documents)}")

    print(f"Loading embedding model: {MODEL_NAME}")

    model = SentenceTransformer(MODEL_NAME)

    texts = [document["text"] for document in documents]

    print("Generating embeddings...")

    embeddings = model.encode(
        texts,
        batch_size=32,
        show_progress_bar=True,
        normalize_embeddings=True,
    )

    embeddings = np.asarray(embeddings, dtype=np.float32)

    print(f"Embedding shape: {embeddings.shape}")

    np.save(EMBEDDINGS_FILE, embeddings)

    metadata = []

    for document in documents:
        metadata.append({
            "id": document["id"],
            "metadata": document["metadata"],
            "text": document["text"],
        })

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(
            metadata,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print()
    print("Embedding generation complete.")
    print(f"Embeddings: {EMBEDDINGS_FILE}")
    print(f"Metadata:   {METADATA_FILE}")


if __name__ == "__main__":
    main()
