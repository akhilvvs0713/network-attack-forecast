import re
from typing import Any, Dict, List, Optional


# Dictionary of well-known network flow telemetry features to clean, objective descriptions.
# Features not in this dictionary will simply retain their raw name as attribution evidence.
KNOWN_FEATURE_SEMANTICS: Dict[str, str] = {
    "smb_pipe_access": "SMB named pipe access",
    "inter_arrival_time_min": "inter-arrival packet timing anomalies",
    "flow_iat_mean": "mean flow inter-arrival time",
    "flow_iat_std": "flow inter-arrival time variance",
    "std_flow iat std": "flow inter-arrival time standard deviation",
    "ttl_variance": "IP Time-to-Live (TTL) variance",
    "dst_port_dispersion": "destination port dispersion / multi-port scanning pattern",
    "tcp_syn_ratio": "abnormal TCP SYN packet ratio",
    "tcp_window_zero_count": "TCP zero window size indicators",
    "payload_entropy": "packet payload byte entropy",
    "mean_dst port": "destination port targeting",
    "mean_flow duration": "flow duration anomaly",
    "max_totlen fwd pkts": "high forward packet volume",
    "max_subflow fwd byts": "elevated forward byte transmission",
    "max_bwd pkt len std": "backward packet length variation",
    "mean_down/up ratio": "asymmetric download-to-upload ratio",
}


def _clean_feature_name(name: str) -> str:
    """Normalize feature name for lookup while preserving original."""
    return name.strip().lower()


def _extract_technique_id(stage_str: str) -> Optional[str]:
    """Extract explicit MITRE technique ID like T1021.002 or T1190 if embedded in stage."""
    match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", stage_str, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return None


def _clean_stage_name(stage_str: str) -> str:
    """Strip IDs or parenthetical codes from stage for clean tactic phrasing."""
    cleaned = re.sub(r"\(.*?\)", "", stage_str).strip()
    return cleaned if cleaned else stage_str.strip()


def _enrich_stage_context(cleaned_stage: str) -> str:
    """
    Enrich domain stage names with canonical MITRE ATT&CK concepts.
    For example, 'Web Exploit' in ATT&CK enterprise terminology corresponds to
    'Exploitation of Public-Facing Application' under Initial Access.
    """
    low = cleaned_stage.lower()
    if "web exploit" in low:
        if "initial access" not in low:
            return "Initial Access - Exploitation of Public-Facing Application (Web Exploit)"
        return f"{cleaned_stage} - Exploitation of Public-Facing Application"
    if "c2" in low or "botnet" in low:
        if "command and control" not in low:
            return f"Command and Control ({cleaned_stage})"
    return cleaned_stage


def build_rag_query(lstm_output: Dict[str, Any]) -> str:
    """
    Build a behavior-rich semantic query for MITRE ATT&CK retrieval dynamically
    from the LSTM output and its feature attributions.

    Integrates:
      1. Predicted attack stage/tactic
      2. Any explicit technique ID in the stage string (e.g., T1021.002)
      3. Observed or network behavior if present
      4. Key model attribution features (shap_features / important_features)
      5. Forward-looking trajectory progression
      6. Risk level context
    """
    if not isinstance(lstm_output, dict):
        raise TypeError("lstm_output must be a dictionary.")

    parts: List[str] = []

    # ---------------------------------------------------------
    # 1. Predicted attack stage / tactic & explicit technique ID
    # ---------------------------------------------------------
    raw_stage = (
        lstm_output.get("predicted_category")
        or lstm_output.get("current_stage")
        or lstm_output.get("attack_stage")
        or lstm_output.get("stage")
    )

    explicit_tech_id: Optional[str] = None
    cleaned_stage = ""
    if raw_stage:
        raw_stage_str = str(raw_stage).strip()
        explicit_tech_id = _extract_technique_id(raw_stage_str)
        cleaned_stage = _clean_stage_name(raw_stage_str)
        enriched_stage = _enrich_stage_context(cleaned_stage)

        if explicit_tech_id:
            parts.append(
                f"Predicted attack stage is {enriched_stage} (associated with ATT&CK technique {explicit_tech_id})."
            )
        else:
            parts.append(f"Predicted attack stage is {enriched_stage}.")

    # ---------------------------------------------------------
    # 2. Observed behavior or explicit network behavior
    # ---------------------------------------------------------
    behavior = (
        lstm_output.get("behavior")
        or lstm_output.get("observed_behavior")
        or lstm_output.get("description")
    )
    if behavior:
        parts.append(f"Observed behavior: {str(behavior).strip()}")

    network_behavior = lstm_output.get("network_behavior")
    if network_behavior:
        parts.append(f"Network behavior: {str(network_behavior).strip()}")

    # ---------------------------------------------------------
    # 3. Feature Attributions (shap_features / important_features)
    # ---------------------------------------------------------
    raw_features = (
        lstm_output.get("shap_features")
        or lstm_output.get("important_features")
        or []
    )

    feature_phrases = []
    has_smb_feature = False
    if isinstance(raw_features, list) and len(raw_features) > 0:
        for item in raw_features[:5]:
            if not isinstance(item, dict):
                continue
            feat_name = str(item.get("feature", "")).strip()
            importance = item.get("importance")

            if not feat_name:
                continue

            cleaned_key = _clean_feature_name(feat_name)
            sem_desc = KNOWN_FEATURE_SEMANTICS.get(cleaned_key)
            if "smb" in cleaned_key:
                has_smb_feature = True

            if importance is not None:
                try:
                    imp_val = float(importance)
                    imp_str = f" (attribution: {imp_val:.2f})"
                except (ValueError, TypeError):
                    imp_str = ""
            else:
                imp_str = ""

            if sem_desc:
                feature_phrases.append(f"{feat_name} ({sem_desc}{imp_str})")
            else:
                feature_phrases.append(f"{feat_name}{imp_str}")

        if feature_phrases:
            parts.append(
                "Key model-attribution telemetry features: "
                + ", ".join(feature_phrases)
                + "."
            )

    # If no explicit behavior string was provided, synthesize objective behavioral context
    # based on the stage and recognized attribution features
    if not behavior and not network_behavior and raw_stage:
        stage_low = cleaned_stage.lower()
        if "lateral" in stage_low and has_smb_feature:
            parts.append("Network behavior indicates lateral movement involving SMB communication between internal hosts.")
        elif "initial access" in stage_low or "web exploit" in stage_low:
            parts.append("Network behavior indicates initial access targeting public-facing application services.")
        elif "dos" in stage_low or "impact" in stage_low:
            parts.append("Network behavior indicates denial of service volumetric flood disrupting service availability.")
        elif "c2" in stage_low or "command" in stage_low:
            parts.append("Network behavior indicates external command and control channel communication.")
        elif "credential" in stage_low:
            parts.append("Network behavior indicates credential dumping or password harvesting activity.")

    # ---------------------------------------------------------
    # 4. Trajectory Progression
    # ---------------------------------------------------------
    trajectory = lstm_output.get("trajectory")
    if isinstance(trajectory, list) and len(trajectory) > 0:
        future_stages: List[str] = []
        for step in trajectory:
            if not isinstance(step, dict):
                continue
            st = step.get("stage")
            if st:
                cleaned_st = _clean_stage_name(str(st))
                if (
                    cleaned_st.lower() not in ["normal operation", "benign", "unknown", "collecting context..."]
                    and (not future_stages or future_stages[-1] != cleaned_st)
                ):
                    future_stages.append(cleaned_st)

        if future_stages:
            parts.append(
                "Future trajectory indicates progression toward: "
                + " -> ".join(future_stages)
                + "."
            )

    # ---------------------------------------------------------
    # 5. Risk context
    # ---------------------------------------------------------
    risk = (
        lstm_output.get("current_risk")
        or lstm_output.get("risk_score")
        or lstm_output.get("risk")
    )
    if risk is not None:
        try:
            risk_val = float(risk)
            if risk_val >= 0.7:
                parts.append(f"Assessed anomalous risk score is elevated ({risk_val:.2f}).")
        except (ValueError, TypeError):
            pass

    # ---------------------------------------------------------
    # Validate
    # ---------------------------------------------------------
    if not parts:
        raise ValueError(
            "LSTM output does not contain enough behavioral or telemetry information "
            "to build a MITRE retrieval query."
        )

    return "\n".join(parts)


if __name__ == "__main__":
    example = {
        "metadata": {
            "name": "Slow Port Reconnaissance to Lateral SMB Movement",
            "target_asset": "192.168.1.50 (Critical CII Scada Gateway)",
        },
        "step_index": 3,
        "current_risk": 0.89,
        "current_stage": "Lateral Movement (T1021.002)",
        "trajectory": [
            {"step_ahead": "+2s", "prob": 0.92, "stage": "Lateral Movement"},
            {"step_ahead": "+4s", "prob": 0.95, "stage": "C2 Channel"},
            {"step_ahead": "+6s", "prob": 0.98, "stage": "Exfiltration"},
        ],
        "shap_features": [
            {"feature": "smb_pipe_access", "importance": 0.94},
            {"feature": "inter_arrival_time_min", "importance": 0.79},
            {"feature": "ttl_variance", "importance": 0.68},
        ],
    }

    query = build_rag_query(example)
    print("\n" + "=" * 80)
    print("GENERATED BEHAVIOR-RICH RAG QUERY")
    print("=" * 80)
    print(query)
