from typing import Any, Dict, List

from mitre_rag.retrieval.query_builder import build_rag_query
from mitre_rag.retrieval.retriever import MITRERetriever


class MITRERAGPipeline:
    """
    End-to-end MITRE ATT&CK retrieval pipeline.

    Pipeline:

        LSTM output
            ↓
        Query Builder
            ↓
        FAISS semantic retrieval
            ↓
        ATT&CK tactic-aware reranking
            ↓
        Final MITRE techniques
    """

    def __init__(
        self,
        top_k: int = 5,
        retrieval_k: int = 10,
        tactic_boost: float = 0.10,
    ):
        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        if retrieval_k < top_k:
            raise ValueError(
                "retrieval_k must be greater than or equal to top_k."
            )

        self.top_k = top_k
        self.retrieval_k = retrieval_k
        self.tactic_boost = tactic_boost

        self.retriever = MITRERetriever()

    # ---------------------------------------------------------
    # Extract predicted tactic
    # ---------------------------------------------------------

    @staticmethod
    def _extract_tactic(lstm_output: Dict[str, Any]):
        """
        Extract the LSTM predicted attack stage/tactic.

        Example:
            "Lateral Movement (TA0008)"
        """

        stage = (
            lstm_output.get("predicted_category")
            or lstm_output.get("current_stage")
            or lstm_output.get("attack_stage")
            or lstm_output.get("stage")
        )

        if not stage:
            return None

        return str(stage).strip().lower()

    # ---------------------------------------------------------
    # Normalize tactic
    # ---------------------------------------------------------

    @staticmethod
    def _normalize_tactic(tactic: str) -> str:
        """
        Convert the LSTM's human-readable attack stage/tactic
        into the tactic naming used by the MITRE ATT&CK dataset.

        Examples:

            "Lateral Movement (TA0008)"
                -> "lateral-movement"

            "Credential Access (TA0006)"
                -> "credential-access"

            "DoS Impact (TA0040)"
                -> "impact"

            "DDoS Impact (TA0040)"
                -> "impact"

            "Web Exploit (TA0001)"
                -> "initial-access"

            "C2 / Botnet (TA0011)"
                -> "command-and-control"
        """

        if not tactic:
            return ""

        tactic = str(tactic).lower().strip()

        # Remove ATT&CK tactic ID.
        #
        # Example:
        # "lateral movement (ta0008)"
        # becomes:
        # "lateral movement"

        if "(" in tactic:
            tactic = tactic.split("(", 1)[0].strip()

        mappings = {

            # LSTM class 1
            "credential access":
                "credential-access",

            # LSTM classes 2 and 3
            "dos impact":
                "impact",

            "ddos impact":
                "impact",

            # LSTM class 4
            "web exploit":
                "initial-access",

            # LSTM class 5
            "lateral movement":
                "lateral-movement",

            # LSTM class 6
            "c2 / botnet":
                "command-and-control",

            "c2/botnet":
                "command-and-control",

            "c2":
                "command-and-control",

            "botnet":
                "command-and-control",

            "command and control":
                "command-and-control",

            "command & control":
                "command-and-control",

            # Other MITRE tactics
            "initial access":
                "initial-access",

            "execution":
                "execution",

            "persistence":
                "persistence",

            "privilege escalation":
                "privilege-escalation",

            "defense evasion":
                "defense-evasion",

            "discovery":
                "discovery",

            "collection":
                "collection",

            "exfiltration":
                "exfiltration",

            "impact":
                "impact",

            "reconnaissance":
                "reconnaissance",

            "resource development":
                "resource-development",

            # Already-normalized names
            "credential-access":
                "credential-access",

            "lateral-movement":
                "lateral-movement",

            "command-and-control":
                "command-and-control",

            "initial-access":
                "initial-access",

            "privilege-escalation":
                "privilege-escalation",

            "defense-evasion":
                "defense-evasion",

            "resource-development":
                "resource-development",
        }

        return mappings.get(tactic, tactic)

    # ---------------------------------------------------------
    # Tactic-aware reranking
    # ---------------------------------------------------------

    def _rerank_by_tactic(
        self,
        results: List[Dict[str, Any]],
        predicted_tactic: str | None,
    ) -> List[Dict[str, Any]]:
        """
        Boost retrieved techniques whose ATT&CK tactic matches
        the tactic predicted by the LSTM.
        """

        if not predicted_tactic:
            return results[:self.top_k]

        normalized_tactic = self._normalize_tactic(
            predicted_tactic
        )

        reranked = []

        for result in results:

            semantic_score = result["score"]

            tactics = [
                str(tactic).lower().strip()
                for tactic in result.get("tactics", [])
            ]

            tactic_match = normalized_tactic in tactics

            final_score = semantic_score

            if tactic_match:
                final_score += self.tactic_boost

            updated_result = dict(result)

            updated_result["semantic_score"] = semantic_score
            updated_result["tactic_match"] = tactic_match
            updated_result["final_score"] = final_score

            reranked.append(updated_result)

        # Highest final score first.
        reranked.sort(
            key=lambda result: result["final_score"],
            reverse=True,
        )

        # Recalculate ranks.
        for rank, result in enumerate(
            reranked[:self.top_k],
            start=1,
        ):
            result["rank"] = rank

        return reranked[:self.top_k]

    # ---------------------------------------------------------
    # Main pipeline
    # ---------------------------------------------------------

    def run(
        self,
        lstm_output: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute the complete LSTM → RAG pipeline.
        """

        # Step 1:
        # Build semantic security query.
        query = build_rag_query(lstm_output)

        # Step 2:
        # Extract LSTM predicted tactic.
        predicted_tactic = self._extract_tactic(
            lstm_output
        )

        # Step 3:
        # Retrieve more candidates than we finally need.
        semantic_results = self.retriever.search(
            query,
            top_k=self.retrieval_k,
        )

        # Step 4:
        # Rerank using ATT&CK tactic.
        final_results = self._rerank_by_tactic(
            semantic_results,
            predicted_tactic,
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
# Pretty printing
# =============================================================

def print_results(output: Dict[str, Any]):

    print("\n" + "=" * 80)
    print("GENERATED RAG QUERY")
    print("=" * 80)

    print(output["query"])

    print("\n" + "=" * 80)
    print("TACTIC")
    print("=" * 80)

    print(
        f"LSTM tactic:       "
        f"{output['predicted_tactic']}"
    )

    print(
        f"Normalized tactic: "
        f"{output['normalized_tactic']}"
    )

    print("\n" + "=" * 80)
    print("MITRE ATT&CK RESULTS")
    print("=" * 80)

    for result in output["results"]:

        print(
            f"\n#{result['rank']} "
            f"{result['technique_id']} - "
            f"{result['name']}"
        )

        print(
            f"Semantic score: {result['semantic_score']:.4f}"
        )

        print(
            f"Tactic match:   {result['tactic_match']}"
        )

        print(
            f"Final score:    {result['final_score']:.4f}"
        )

        print(
            f"Tactics:        "
            f"{', '.join(result['tactics'])}"
        )

        print(
            f"Sub-technique:  "
            f"{result['is_subtechnique']}"
        )

        print(
            f"URL:            "
            f"{result['url']}"
        )


# =============================================================
# Test
# =============================================================

def main():

    # Synthetic LSTM output.
    #
    # This is NOT training data.
    # It is only used to test the RAG pipeline.

    lstm_output = {

        "risk_score": 0.91,

        "predicted_category":
            "Lateral Movement (TA0008)",

        "important_features": [
            {
                "feature": "mean_Dst Port",
                "importance": 1.0,
            },
            {
                "feature": "mean_Flow Duration",
                "importance": 0.72,
            },
            {
                "feature": "mean_Total Fwd Packets",
                "importance": 0.61,
            },
        ],

        "trajectory": [
            {
                "step": 1,
                "stage": "Lateral Movement (TA0008)",
            },
            {
                "step": 2,
                "stage": "Lateral Movement (TA0008)",
            },
            {
                "step": 3,
                "stage": "Lateral Movement (TA0008)",
            },
        ],

        "behavior": (
            "Repeated connections between internal Windows "
            "hosts using SMB-like traffic."
        ),
    }

    pipeline = MITRERAGPipeline(
        top_k=5,
        retrieval_k=10,
        tactic_boost=0.10,
    )

    output = pipeline.run(lstm_output)

    print_results(output)


if __name__ == "__main__":
    main()
