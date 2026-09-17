import json
from pathlib import Path

import faiss
import numpy as np


BASE_DIR = Path(__file__).resolve().parents[1]

EMBEDDINGS_FILE = BASE_DIR / "data" / "embeddings" / "embeddings.npy"
METADATA_FILE = BASE_DIR / "data" / "embeddings" / "metadata.json"

OUTPUT_DIR = BASE_DIR / "vectorstore"
INDEX_FILE = OUTPUT_DIR / "mitre.index"
METADATA_OUTPUT = OUTPUT_DIR / "metadata.json"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading embeddings...")
    embeddings = np.load(EMBEDDINGS_FILE).astype("float32")

    print(f"Embedding shape: {embeddings.shape}")

    if embeddings.ndim != 2:
        raise ValueError("Embeddings must be a 2D matrix.")

    dimension = embeddings.shape[1]

    print(f"Vector dimension: {dimension}")

    # We normalized the embeddings during generation.
    # Inner product therefore behaves like cosine similarity.
    index = faiss.IndexFlatIP(dimension)

    index.add(embeddings)

    print(f"Vectors added: {index.ntotal}")

    print("Loading metadata...")

    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    if len(metadata) != index.ntotal:
        raise ValueError(
            f"Metadata count ({len(metadata)}) does not match "
            f"vector count ({index.ntotal})."
        )

    faiss.write_index(index, str(INDEX_FILE))

    with open(METADATA_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(
            metadata,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print()
    print("FAISS index created successfully.")
    print(f"Index:    {INDEX_FILE}")
    print(f"Metadata: {METADATA_OUTPUT}")


if __name__ == "__main__":
    main()
