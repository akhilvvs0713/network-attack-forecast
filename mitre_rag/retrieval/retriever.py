import json
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer


BASE_DIR = Path(__file__).resolve().parents[1]

INDEX_FILE = BASE_DIR / "vectorstore" / "mitre.index"
METADATA_FILE = BASE_DIR / "vectorstore" / "metadata.json"

MODEL_NAME = "all-MiniLM-L6-v2"


class MITRERetriever:
    def __init__(
        self,
        index_file=INDEX_FILE,
        metadata_file=METADATA_FILE,
        model_name=MODEL_NAME,
    ):
        print("Loading MITRE vector index...")

        self.index = faiss.read_index(str(index_file))

        with open(metadata_file, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        if self.index.ntotal != len(self.metadata):
            raise ValueError(
                f"Index contains {self.index.ntotal} vectors, "
                f"but metadata contains {len(self.metadata)} records."
            )

        print(f"Loaded {self.index.ntotal} MITRE vectors.")

        print(f"Loading embedding model: {model_name}")

        self.model = SentenceTransformer(model_name)

    def search(self, query: str, top_k: int = 5):
        """
        Search MITRE ATT&CK techniques using semantic similarity.
        """

        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        top_k = min(top_k, self.index.ntotal)

        query_embedding = self.model.encode(
            [query],
            normalize_embeddings=True,
        )

        distances, indices = self.index.search(
            query_embedding,
            top_k,
        )

        results = []

        for score, index in zip(distances[0], indices[0]):
            if index < 0:
                continue

            document = self.metadata[index]

            results.append({
                "rank": len(results) + 1,
                "score": float(score),
                "technique_id": document["metadata"]["technique_id"],
                "name": document["metadata"]["name"],
                "tactics": document["metadata"]["tactics"],
                "is_subtechnique": document["metadata"]["is_subtechnique"],
                "url": document["metadata"]["url"],
                "text": document["text"],
            })

        return results


def main():
    retriever = MITRERetriever()

    test_queries = [
        "Repeated SMB connections between internal Windows hosts",
        "Large volume of traffic causing denial of service",
        "Stealing usernames and passwords from a compromised system",
        "Command and control communication with a remote server",
    ]

    for query in test_queries:
        print("\n" + "=" * 80)
        print(f"QUERY: {query}")
        print("=" * 80)

        results = retriever.search(query, top_k=5)

        for result in results:
            print(
                f"\n#{result['rank']} "
                f"{result['technique_id']} - {result['name']}"
            )

            print(f"Score:   {result['score']:.4f}")
            print(f"Tactics: {', '.join(result['tactics'])}")


if __name__ == "__main__":
    main()
