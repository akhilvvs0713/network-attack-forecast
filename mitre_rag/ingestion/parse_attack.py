import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
STIX_DIR = BASE_DIR / "data" / "attack-stix-data"
OUTPUT_FILE = BASE_DIR / "data" / "mitre_techniques.jsonl"


def find_enterprise_bundle():
    """
    Find the Enterprise ATT&CK STIX bundle.
    """

    candidates = list(STIX_DIR.rglob("enterprise-attack.json"))

    if not candidates:
        raise FileNotFoundError(
            "Could not find enterprise-attack.json inside "
            f"{STIX_DIR}"
        )

    # Prefer the normal STIX bundle location if multiple exist.
    return candidates[0]


def extract_techniques(bundle_path):
    """
    Extract ATT&CK attack-pattern objects representing
    Enterprise techniques and sub-techniques.
    """

    with open(bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    techniques = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Ignore revoked/deprecated ATT&CK objects.
        if obj.get("revoked", False):
            continue

        if obj.get("x_mitre_deprecated", False):
            continue

        # Keep Enterprise ATT&CK techniques/sub-techniques.
        external_refs = obj.get("external_references", [])

        technique_id = None

        for ref in external_refs:
            source_name = ref.get("source_name")

            if source_name == "mitre-attack":
                external_id = ref.get("external_id", "")

                if external_id.startswith("T"):
                    technique_id = external_id
                    break

        if not technique_id:
            continue

        name = obj.get("name", "").strip()
        description = obj.get("description", "").strip()

        if not name or not description:
            continue

        # Determine whether this is a sub-technique.
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))

        # Extract tactics from kill_chain_phases.
        tactics = []

        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")

                if phase_name:
                    tactics.append(phase_name)

        # Remove duplicates while preserving order.
        tactics = list(dict.fromkeys(tactics))

        # Extract ATT&CK URLs where available.
        attack_url = None

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                attack_url = ref.get("url")
                break

        technique = {
            "technique_id": technique_id,
            "name": name,
            "description": description,
            "tactics": tactics,
            "is_subtechnique": is_subtechnique,
            "url": attack_url,
        }

        techniques.append(technique)

    return techniques


def write_jsonl(techniques):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for technique in techniques:
            f.write(json.dumps(technique, ensure_ascii=False) + "\n")


def main():
    bundle_path = find_enterprise_bundle()

    print(f"Using MITRE bundle:")
    print(f"  {bundle_path}")

    techniques = extract_techniques(bundle_path)

    print(f"Extracted techniques: {len(techniques)}")

    write_jsonl(techniques)

    print(f"Written to:")
    print(f"  {OUTPUT_FILE}")

    print("\nFirst 5 techniques:")

    for technique in techniques[:5]:
        print(
            f"  {technique['technique_id']} - "
            f"{technique['name']}"
        )


if __name__ == "__main__":
    main()
