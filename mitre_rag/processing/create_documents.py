import json
import re
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]

INPUT_FILE = BASE_DIR / "data" / "mitre_techniques.jsonl"
OUTPUT_FILE = BASE_DIR / "data" / "mitre_documents.jsonl"


def clean_text(text: str) -> str:
    """Clean Markdown/HTML artifacts from ATT&CK descriptions."""

    # Remove HTML tags.
    text = re.sub(r"<[^>]+>", " ", text)

    # Convert Markdown links to their visible text.
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)

    # Remove ATT&CK citation markers.
    text = re.sub(r"\(Citation:[^)]+\)", "", text)

    # Normalize whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def build_document(technique: dict) -> dict:
    tactics = technique.get("tactics", [])

    tactic_text = ", ".join(
        tactic.replace("-", " ").title()
        for tactic in tactics
    )

    technique_type = (
        "Sub-technique"
        if technique.get("is_subtechnique")
        else "Technique"
    )

    text = (
        f"Technique ID: {technique['technique_id']}\n"
        f"Technique: {technique['name']}\n"
        f"Tactics: {tactic_text}\n"
        f"Type: {technique_type}\n\n"
        f"Description:\n"
        f"{clean_text(technique['description'])}"
    )

    return {
        "id": technique["technique_id"],
        "text": text,
        "metadata": {
            "technique_id": technique["technique_id"],
            "name": technique["name"],
            "tactics": tactics,
            "is_subtechnique": technique["is_subtechnique"],
            "url": technique["url"],
        },
    }


def main():
    documents = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            technique = json.loads(line)

            document = build_document(technique)

            documents.append(document)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for document in documents:
            f.write(
                json.dumps(
                    document,
                    ensure_ascii=False
                )
                + "\n"
            )

    print(f"Created {len(documents)} RAG documents")
    print(f"Output: {OUTPUT_FILE}")

    print("\nExample document:\n")
    print(documents[0]["text"])


if __name__ == "__main__":
    main()
