import re
from typing import Any, Dict, List, Optional, Tuple

from mitre_rag.retrieval.query_builder import build_rag_query
from mitre_rag.retrieval.retriever import MITRERetriever


# Defensive limitations tailored by technique category
LIMITATIONS_MAP = {
    "T1021.002": "Network flow telemetry alone cannot confirm whether SMB traffic represents authorized administrative activity, internal tool usage, or malicious lateral movement without host event logs (e.g. Sysmon Event ID 17/18 for Named Pipes).",
    "T1021.001": "Flow-level RDP metrics indicate interactive remote desktop sessions but cannot distinguish authorized administrative remote logins from unauthorized lateral traversal without Windows Security Event 4624 (Logon Type 10).",
    "T1190": "Flow-level traffic indicates HTTP/HTTPS requests directed at application endpoints, but full payload inspection and web server access/error logs are required to confirm successful vulnerability exploitation.",
    "T1498": "High-volume traffic patterns suggest network denial of service, but volumetric surges can occasionally result from legitimate network backups, misconfigurations, or flash crowds.",
    "T1498.001": "Direct packet flood characteristics match volumetric DoS heuristics, though transit-provider congestion or legitimate load testing may present similar flow profiles.",
    "T1003": "Telemetry anomalies align with credential extraction timing, but host memory auditing (e.g. LSASS handle access, Event 4656) is mandatory to verify unauthorized credential access.",
    "T1071.001": "Periodic outbound HTTP/HTTPS sessions match command-and-control beaconing heuristics, but benign heartbeat polling from legitimate software agents can exhibit identical timing patterns.",
    "default": "Network flow features and model attribution provide behavioral heuristics but cannot conclusively confirm malicious intent without correlated host logs and endpoint telemetry."
}


class MITRERAGPipeline:
    """
    End-to-end MITRE ATT&CK retrieval, reranking, and evidence-grounded explanation pipeline.

    Pipeline Flow:
        LSTM telemetry & attribution output
            ↓
        Behavior-rich query builder
            ↓
        Sentence-Transformers (all-MiniLM-L6-v2) embedding
            ↓
        FAISS IndexFlatIP semantic candidate retrieval (k=40)
            ↓
        Tactic-aware reranking
            ↓
        Evidence & feature-attribution grounded reranking
            ↓
        Calibrated multi-factor confidence assessment
            ↓
        Evidence-grounded explanation & defensive limitations
    """

    def __init__(
        self,
        top_k: int = 5,
        retrieval_k: int = 60,
        tactic_boost: float = 0.12,
        evidence_boost_max: float = 0.20,
    ):
        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        if retrieval_k < top_k:
            raise ValueError(
                "retrieval_k must be greater than or equal to top_k."
            )

        self.top_k = top_k
        self.retrieval_k = max(retrieval_k, 50)
        self.tactic_boost = tactic_boost
        self.evidence_boost_max = evidence_boost_max

        self.retriever = MITRERetriever()

    # ---------------------------------------------------------
    # Extract predicted tactic & technique hints
    # ---------------------------------------------------------

    @staticmethod
    def _extract_tactic(lstm_output: Dict[str, Any]) -> Optional[str]:
        stage = (
            lstm_output.get("predicted_category")
            or lstm_output.get("current_stage")
            or lstm_output.get("attack_stage")
            or lstm_output.get("stage")
        )
        if not stage:
            return None
        return str(stage).strip().lower()

    @staticmethod
    def _extract_explicit_technique_id(stage_str: Optional[str]) -> Optional[str]:
        if not stage_str:
            return None
        match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", stage_str, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return None

    # ---------------------------------------------------------
    # Normalize tactic
    # ---------------------------------------------------------

    @staticmethod
    def _normalize_tactic(tactic: str) -> str:
        """
        Convert human-readable attack stage/tactic names into
        the MITRE ATT&CK enterprise dataset tactic slugs.
        """
        if not tactic:
            return ""

        t = str(tactic).lower().strip()
        if "(" in t:
            t = t.split("(", 1)[0].strip()

        # Resilient substring matching handles compound strings like "Initial Access / Web Exploit"
        if "credential" in t or "password" in t:
            return "credential-access"
        if "lateral" in t:
            return "lateral-movement"
        if "dos" in t or "ddos" in t or "impact" in t:
            return "impact"
        if "web exploit" in t or "initial access" in t:
            return "initial-access"
        if "c2" in t or "command" in t or "botnet" in t:
            return "command-and-control"
        if "privilege" in t:
            return "privilege-escalation"
        if "evasion" in t:
            return "defense-evasion"
        if "recon" in t:
            return "reconnaissance"
        if "discovery" in t:
            return "discovery"
        if "execution" in t:
            return "execution"
        if "persistence" in t:
            return "persistence"
        if "collection" in t:
            return "collection"
        if "exfiltration" in t:
            return "exfiltration"
        if "resource" in t:
            return "resource-development"

        return t.replace(" ", "-")

    # ---------------------------------------------------------
    # Evidence-grounded scoring
    # ---------------------------------------------------------

    def _compute_evidence_score(
        self,
        candidate: Dict[str, Any],
        lstm_output: Dict[str, Any],
        explicit_id: Optional[str],
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate an evidence grounding score based on alignment between
        model feature attributions / behavioral description and candidate technique.

        Returns (evidence_score, matched_evidence_list).
        """
        technique_id = candidate.get("technique_id", "")
        technique_name = candidate.get("name", "").lower()
        technique_text = candidate.get("text", "").lower()
        full_doc = f"{technique_name} {technique_text}"

        evidence_score = 0.0
        evidence_list: List[Dict[str, Any]] = []

        # 1. Exact technique ID match if present in the LSTM stage (e.g. T1021.002)
        if explicit_id:
            if technique_id == explicit_id:
                evidence_score += 0.12
            elif technique_id.startswith(explicit_id + ".") or explicit_id.startswith(technique_id + "."):
                evidence_score += 0.08

        # 2. Match model attribution features (shap_features / important_features)
        raw_features = (
            lstm_output.get("shap_features")
            or lstm_output.get("important_features")
            or []
        )

        for feat in raw_features:
            if not isinstance(feat, dict):
                continue
            fname = str(feat.get("feature", "")).lower()
            try:
                imp = float(feat.get("importance", 0.0))
            except (ValueError, TypeError):
                imp = 0.5

            if not fname:
                continue

            # Check SMB indicators
            if any(term in fname for term in ["smb", "pipe"]):
                if any(term in full_doc for term in ["smb", "pipe", "admin share", "445"]):
                    evidence_score += 0.08 * imp
                    evidence_list.append({"feature": feat.get("feature"), "importance": imp})

            # Check Port scanning / Discovery indicators
            elif "dst_port" in fname or "port" in fname:
                if any(term in full_doc for term in ["port", "scan", "service"]):
                    evidence_score += 0.04 * imp
                    evidence_list.append({"feature": feat.get("feature"), "importance": imp})

            # Check DoS indicators
            elif any(term in fname for term in ["totlen", "byts", "pkt len", "flow duration"]):
                if any(term in full_doc for term in ["flood", "traffic", "denial", "bandwidth"]):
                    evidence_score += 0.04 * imp
                    evidence_list.append({"feature": feat.get("feature"), "importance": imp})

            # Default: feature name directly matches terms in the technique text
            elif any(part in full_doc for part in fname.split("_") if len(part) > 3):
                evidence_score += 0.03 * imp
                evidence_list.append({"feature": feat.get("feature"), "importance": imp})

        # 3. Behavioral keyword & concept alignment (from behavior, stage, description, network_behavior)
        stage_text = str(
            lstm_output.get("predicted_category")
            or lstm_output.get("current_stage")
            or ""
        ).lower()

        behavior_text = (
            stage_text
            + " "
            + str(lstm_output.get("behavior") or "")
            + " "
            + str(lstm_output.get("observed_behavior") or "")
            + " "
            + str(lstm_output.get("network_behavior") or "")
        ).lower()

        if behavior_text:
            # Case A: Web Exploit / Application Exploitation (T1190)
            # Differentiates server-side application exploitation from client-side drive-by browsing
            if ("exploit" in behavior_text or "web exploit" in behavior_text) and any(w in behavior_text for w in ["web", "http", "application", "server"]):
                # Technique title explicitly specifies exploit of application
                if "exploit" in technique_name and "application" in technique_name:
                    evidence_score += 0.15
                elif "exploit" in technique_name or "application" in technique_name:
                    evidence_score += 0.05

                # Technique body covers internet-facing host/system/web server
                if any(w in full_doc for w in ["public-facing", "internet-facing", "websites/web servers", "software bug"]):
                    evidence_score += 0.05

            # Case B: SMB / Windows Host Lateral Movement (T1021.002)
            if "smb" in behavior_text or "named pipe" in behavior_text:
                if any(w in technique_name for w in ["smb", "admin share", "named pipe"]):
                    evidence_score += 0.14
                elif any(w in full_doc for w in ["smb", "admin share", "pipe", "445"]):
                    evidence_score += 0.06

            # Case C: Network Flooding / Denial of Service (T1498 / T1498.001)
            if any(w in behavior_text for w in ["flood", "flooding", "large volume", "denial of service"]):
                if "network denial of service" in technique_name or "flood" in technique_name:
                    evidence_score += 0.14
                elif any(w in full_doc for w in ["flood", "denial of service", "exhaustion"]):
                    evidence_score += 0.06

            # Case D: OS Credential Dumping (T1003)
            # Extracts passwords/hashes from Windows/OS structures (SAM, LSASS, etc.)
            if any(w in behavior_text for w in ["password", "hash", "passwords", "hashes", "credential"]):
                if "credential dumping" in technique_name or any(w in technique_name for w in ["security account manager", "lsa secrets", "cached domain credentials"]):
                    evidence_score += 0.15
                elif any(w in full_doc for w in ["dump credentials", "sam", "lsass", "hashes"]):
                    evidence_score += 0.06

            # Case E: C2 over HTTP/HTTPS / Web Protocols (T1071.001)
            if any(w in behavior_text for w in ["c2", "remote server", "command and control"]) and any(w in behavior_text for w in ["http", "https", "web"]):
                if "web protocols" in technique_name or ("application layer protocol" in technique_name and "1071" in technique_id):
                    evidence_score += 0.15
                elif any(w in full_doc for w in ["command and control", "c2", "web protocol", "http"]):
                    evidence_score += 0.06

        # Cap evidence score at configured maximum
        evidence_score = min(self.evidence_boost_max, evidence_score)

        # Fallback evidence list if no specific features matched
        if not evidence_list and raw_features:
            for feat in raw_features[:3]:
                if isinstance(feat, dict) and "feature" in feat:
                    evidence_list.append(feat)

        return round(evidence_score, 4), evidence_list

    # ---------------------------------------------------------
    # Calibrated Confidence Score
    # ---------------------------------------------------------

    @staticmethod
    def _calculate_confidence(
        semantic_score: float,
        tactic_match: bool,
        evidence_score: float,
        has_explicit_id: bool,
    ) -> float:
        """
        Compute an explainable, multi-factor confidence metric in [0.0, 1.0].

        Confidence is NOT raw FAISS cosine similarity (which is an embedding distance).
        Instead, it blends:
          - Semantic embedding similarity (40% weight)
          - MITRE ATT&CK tactic alignment (25% weight)
          - Telemetry & feature attribution grounding (25% weight)
          - Direct technique identification bonus (10% weight)
        """
        clamped_sem = max(0.0, min(1.0, semantic_score))

        sem_factor = clamped_sem * 0.40
        tactic_factor = 0.25 if tactic_match else 0.05
        evidence_factor = min(0.25, (evidence_score / 0.15) * 0.25)
        id_factor = 0.10 if has_explicit_id else 0.0

        confidence = sem_factor + tactic_factor + evidence_factor + id_factor
        return round(float(min(0.98, max(0.20, confidence))), 2)

    # ---------------------------------------------------------
    # Tactic & Evidence Reranking
    # ---------------------------------------------------------

    def _rerank_candidates(
        self,
        results: List[Dict[str, Any]],
        predicted_tactic: Optional[str],
        lstm_output: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        normalized_tactic = (
            self._normalize_tactic(predicted_tactic) if predicted_tactic else ""
        )
        explicit_id = self._extract_explicit_technique_id(predicted_tactic)

        reranked = []
        for result in results:
            semantic_score = float(result.get("score", 0.0))

            tactics = [
                str(tactic).lower().strip()
                for tactic in result.get("tactics", [])
            ]
            tactic_match = bool(normalized_tactic and normalized_tactic in tactics)
            tactic_score = self.tactic_boost if tactic_match else 0.0

            evidence_score, evidence_items = self._compute_evidence_score(
                result, lstm_output, explicit_id
            )

            final_retrieval_score = round(
                semantic_score + tactic_score + evidence_score, 4
            )

            confidence = self._calculate_confidence(
                semantic_score=semantic_score,
                tactic_match=tactic_match,
                evidence_score=evidence_score,
                has_explicit_id=bool(
                    explicit_id and result.get("technique_id") == explicit_id
                ),
            )

            updated = dict(result)
            updated["semantic_score"] = round(semantic_score, 4)
            updated["tactic_score"] = round(tactic_score, 4)
            updated["tactic_match"] = tactic_match
            updated["evidence_score"] = evidence_score
            updated["evidence_items"] = evidence_items
            updated["final_score"] = final_retrieval_score
            updated["final_retrieval_score"] = final_retrieval_score
            updated["confidence"] = confidence

            reranked.append(updated)

        # Sort by composite final score descending
        reranked.sort(key=lambda x: x["final_retrieval_score"], reverse=True)

        for rank, res in enumerate(reranked[: self.top_k], start=1):
            res["rank"] = rank

        return reranked[: self.top_k]

    # ---------------------------------------------------------
    # Main retrieval pipeline
    # ---------------------------------------------------------

    def run(self, lstm_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute complete LSTM -> query -> FAISS -> tactic/evidence reranking flow.
        """
        query = build_rag_query(lstm_output)
        predicted_tactic = self._extract_tactic(lstm_output)

        semantic_candidates = self.retriever.search(
            query, top_k=self.retrieval_k
        )

        final_results = self._rerank_candidates(
            semantic_candidates, predicted_tactic, lstm_output
        )

        return {
            "query": query,
            "predicted_tactic": predicted_tactic,
            "normalized_tactic": (
                self._normalize_tactic(predicted_tactic)
                if predicted_tactic
                else None
            ),
            "results": final_results,
        }


# =============================================================
# Clean Explanation & Structured Output Formatter
# =============================================================

def _build_defensive_reason(
    top_result: Dict[str, Any],
    lstm_output: Dict[str, Any],
) -> str:
    tech_name = top_result.get("name", "Unknown Technique")
    tech_id = top_result.get("technique_id", "Unknown ID")
    tactics_str = ", ".join(top_result.get("tactics", []))

    stage = (
        lstm_output.get("current_stage")
        or lstm_output.get("predicted_category")
        or "Observed Activity"
    )

    ev_list = top_result.get("evidence_items", [])
    if ev_list:
        feat_strs = [f"{e.get('feature')} (importance {e.get('importance')})" for e in ev_list[:3]]
        ev_clause = f"Supported by model attribution features: {', '.join(feat_strs)}."
    else:
        ev_clause = "Observed traffic dynamics align with model risk thresholds."

    return (
        f"Telemetry and stage progression ({stage}) are consistent with ATT&CK technique "
        f"{tech_name} ({tech_id}) under tactic(s) [{tactics_str}]. {ev_clause}"
    )


def _get_limitations(technique_id: str) -> str:
    if technique_id in LIMITATIONS_MAP:
        return LIMITATIONS_MAP[technique_id]
    parent_id = technique_id.split(".")[0]
    if parent_id in LIMITATIONS_MAP:
        return LIMITATIONS_MAP[parent_id]
    return LIMITATIONS_MAP["default"]


def run_rag(lstm_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Public entrypoint for the RAG service.
    Takes arbitrary LSTM output dictionary and returns the required structured MITRE response.
    """
    pipeline = MITRERAGPipeline(top_k=5, retrieval_k=40)
    output = pipeline.run(lstm_output)

    results = output.get("results", [])
    if not results:
        return {
            "technique_id": "T0000",
            "technique_name": "No Mapping Found",
            "tactic": output.get("normalized_tactic") or "Unknown",
            "confidence": 0.0,
            "reason": "No MITRE ATT&CK technique met the similarity threshold.",
            "evidence": [],
            "mitre_description": "",
            "limitations": LIMITATIONS_MAP["default"],
            "candidates": [],
        }

    top = results[0]
    tech_id = top.get("technique_id", "")
    tactics = top.get("tactics", [])
    primary_tactic = tactics[0].replace("-", " ").title() if tactics else "Unknown"

    evidence = top.get("evidence_items") or (
        lstm_output.get("shap_features")
        or lstm_output.get("important_features")
        or []
    )

    mitre_desc = top.get("text", "")
    if "Description:" in mitre_desc:
        mitre_desc = mitre_desc.split("Description:", 1)[1].strip()

    return {
        "technique_id": tech_id,
        "technique_name": top.get("name", ""),
        "tactic": primary_tactic,
        "confidence": top.get("confidence", 0.70),
        "scores": {
            "semantic_score": top.get("semantic_score", 0.0),
            "tactic_score": top.get("tactic_score", 0.0),
            "evidence_score": top.get("evidence_score", 0.0),
            "final_retrieval_score": top.get("final_retrieval_score", 0.0),
        },
        "reason": _build_defensive_reason(top, lstm_output),
        "evidence": evidence,
        "mitre_description": mitre_desc[:500] + ("..." if len(mitre_desc) > 500 else ""),
        "limitations": _get_limitations(tech_id),
        "candidates": [
            {
                "rank": r.get("rank"),
                "technique_id": r.get("technique_id"),
                "technique_name": r.get("name"),
                "tactics": r.get("tactics"),
                "confidence": r.get("confidence"),
                "final_score": r.get("final_score"),
            }
            for r in results
        ],
    }


if __name__ == "__main__":
    import json

    example = {
        "metadata": {
            "name": "Slow Port Reconnaissance to Lateral SMB Movement",
            "target_asset": "192.168.1.50 (Critical CII Scada Gateway)",
            "total_windows": 5,
        },
        "current_window": {
            "step_index": 3,
            "timestamp": "10:00:06",
            "flow_count": 612,
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
        },
    }

    res = run_rag(example["current_window"])
    print(json.dumps(res, indent=2))
