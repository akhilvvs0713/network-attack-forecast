import json
from pathlib import Path

from mitre_rag.retrieval.retriever import MITRERetriever


BASE_DIR = Path(__file__).resolve().parents[1]
CASES_FILE = BASE_DIR / "tests" / "retrieval_cases.json"


def is_exact_match(expected, retrieved):
    return expected == retrieved


def is_family_match(expected, retrieved):
    """
    Example:
        expected = T1003
        retrieved = T1003.002

    Both belong to the same ATT&CK technique family.
    """
    if expected == retrieved:
        return True

    # Parent technique -> sub-technique
    if retrieved.startswith(expected + "."):
        return True

    # Sub-technique -> parent technique
    if expected.startswith(retrieved + "."):
        return True

    return False


def evaluate():
    with open(CASES_FILE, "r", encoding="utf-8") as f:
        cases = json.load(f)

    retriever = MITRERetriever()

    exact_matches = 0
    family_matches = 0

    print("\n" + "=" * 70)
    print("MITRE ATT&CK RETRIEVAL EVALUATION")
    print("=" * 70)

    for i, case in enumerate(cases, start=1):

        query = case["query"]
        expected_ids = case["expected"]

        results = retriever.search(query, top_k=5)

        retrieved_ids = [
            result["technique_id"]
            for result in results
        ]

        exact = any(
            expected in retrieved_ids
            for expected in expected_ids
        )

        family = any(
            is_family_match(expected, retrieved)
            for expected in expected_ids
            for retrieved in retrieved_ids
        )

        if exact:
            exact_matches += 1
            family_matches += 1
            status = "EXACT PASS"

        elif family:
            family_matches += 1
            status = "FAMILY PASS"

        else:
            status = "FAIL"

        print(f"\nCase {i}")
        print(f"Query: {query}")
        print(f"Expected: {expected_ids}")
        print(f"Retrieved: {retrieved_ids}")
        print(f"Result: {status}")

        if results:
            print(
                f"Top result: "
                f"{results[0]['technique_id']} - "
                f"{results[0]['name']} "
                f"(score={results[0]['score']:.4f})"
            )

    total = len(cases)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(
        f"Exact matches : {exact_matches}/{total} "
        f"({exact_matches / total * 100:.2f}%)"
    )

    print(
        f"Family matches: {family_matches}/{total} "
        f"({family_matches / total * 100:.2f}%)"
    )


if __name__ == "__main__":
    evaluate()
