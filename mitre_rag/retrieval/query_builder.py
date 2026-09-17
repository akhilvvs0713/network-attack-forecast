from typing import Any, Dict


def build_rag_query(lstm_output: Dict[str, Any]) -> str:
    """
    Build a focused semantic query for MITRE ATT&CK retrieval.

    Only information that describes the observed/predicted
    security behavior should be sent to the embedding model.

    Numerical risk, feature importance and forecast metadata
    are intentionally excluded from the semantic query.
    """

    if not isinstance(lstm_output, dict):
        raise TypeError("lstm_output must be a dictionary.")

    parts = []

    # ---------------------------------------------------------
    # 1. Predicted attack stage / tactic
    # ---------------------------------------------------------

    stage = (
        lstm_output.get("predicted_category")
        or lstm_output.get("current_stage")
        or lstm_output.get("attack_stage")
        or lstm_output.get("stage")
    )

    if stage:
        parts.append(
            f"Attack tactic or stage: {stage}."
        )

    # ---------------------------------------------------------
    # 2. Observed behavior
    # ---------------------------------------------------------

    behavior = (
        lstm_output.get("behavior")
        or lstm_output.get("observed_behavior")
        or lstm_output.get("description")
    )

    if behavior:
        parts.append(
            f"Observed behavior: {behavior}"
        )

    # ---------------------------------------------------------
    # 3. Optional explicit network behavior
    # ---------------------------------------------------------

    network_behavior = lstm_output.get("network_behavior")

    if network_behavior:
        parts.append(
            f"Network behavior: {network_behavior}"
        )

    # ---------------------------------------------------------
    # Validate
    # ---------------------------------------------------------

    if not parts:
        raise ValueError(
            "LSTM output does not contain enough behavioral "
            "information to build a MITRE retrieval query."
        )

    return "\n".join(parts)


if __name__ == "__main__":

    example = {
        "risk_score": 0.91,

        "predicted_category": "Lateral Movement",

        "important_features": [
            {
                "feature": "mean_Dst Port",
                "importance": 1.0,
            },
            {
                "feature": "mean_Flow Duration",
                "importance": 0.72,
            },
        ],

        "trajectory": [
            {
                "step": 1,
                "stage": "Lateral Movement",
            },
            {
                "step": 2,
                "stage": "Lateral Movement",
            },
        ],

        "behavior": (
            "Repeated connections between internal Windows "
            "hosts using SMB-like traffic."
        ),
    }

    query = build_rag_query(example)

    print("\n" + "=" * 80)
    print("GENERATED RAG QUERY")
    print("=" * 80)
    print(query)
