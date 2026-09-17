import json
from pathlib import Path

from mitre_rag.retrieval.rag_pipeline import MITRERAGPipeline


BASE_DIR = Path(__file__).resolve().parents[1]

CASES_FILE = (
    BASE_DIR
    / "tests"
    / "rag_pipeline_cases.json"
)


def is_family_match(expected, retrieved):
    """
    Treat parent/sub-technique relationships as a family match.

    Example:

        T1003
        T1003.002

    belong to the same ATT&CK technique family.
    """

    if expected == retrieved:
        return True

    if retrieved.startswith(expected + "."):
        return True

    if expected.startswith(retrieved + "."):
        return True

    return False


def evaluate():

    with open(
        CASES_FILE,
        "r",
        encoding="utf-8",
    ) as f:

        cases = json.load(f)

    pipeline = MITRERAGPipeline(
        top_k=5,
        retrieval_k=10,
        tactic_boost=0.10,
    )

    exact_pass = 0
    family_pass = 0

    print("\n" + "=" * 80)
    print("LSTM → RAG PIPELINE EVALUATION")
    print("=" * 80)

    for i, case in enumerate(cases, start=1):

        name = case["name"]

        lstm_output = case["lstm_output"]

        expected_ids = case["expected"]

        output = pipeline.run(lstm_output)

        results = output["results"]

        retrieved_ids = [
            result["technique_id"]
            for result in results
        ]

        exact = any(
            expected in retrieved_ids
            for expected in expected_ids
        )

        family = any(
            is_family_match(
                expected,
                retrieved,
            )
            for expected in expected_ids
            for retrieved in retrieved_ids
        )

        if exact:

            exact_pass += 1
            family_pass += 1

            status = "EXACT PASS"

        elif family:

            family_pass += 1

            status = "FAMILY PASS"

        else:

            status = "FAIL"

        print("\n" + "-" * 80)

        print(f"Case {i}: {name}")

        print(
            f"LSTM stage: "
            f"{lstm_output.get('predicted_category')}"
        )

        print(
            f"Expected: "
            f"{expected_ids}"
        )

        print(
            f"Retrieved: "
            f"{retrieved_ids}"
        )

        print(
            f"Result: {status}"
        )

        if results:

            top = results[0]

            print(
                f"Top result: "
                f"{top['technique_id']} - "
                f"{top['name']}"
            )

            print(
                f"Semantic score: "
                f"{top['semantic_score']:.4f}"
            )

            print(
                f"Final score: "
                f"{top['final_score']:.4f}"
            )

            print(
                f"Tactic match: "
                f"{top['tactic_match']}"
            )

    total = len(cases)

    print("\n" + "=" * 80)
    print("FINAL RESULTS")
    print("=" * 80)

    print(
        f"Exact retrieval: "
        f"{exact_pass}/{total} "
        f"({exact_pass / total * 100:.2f}%)"
    )

    print(
        f"Family retrieval: "
        f"{family_pass}/{total} "
        f"({family_pass / total * 100:.2f}%)"
    )


if __name__ == "__main__":
    evaluate()
