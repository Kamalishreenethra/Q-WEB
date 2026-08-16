"""
Baseline Flat Cryptographic Inventory Prioritization Model.
Sorts migration targets purely by algorithm vulnerability and artifact-level risk without graph awareness.
"""
from typing import Any, Dict, List


class FlatCryptographicBaseline:
    """
    Evaluates migration targets using a flat cryptographic inventory strategy.
    Zero graph traversal, zero centrality awareness, and zero transitive dependency tracking.
    """

    def prioritize(self, certificates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts certificates purely by classical algorithm key size and risk score.
        """
        ranked = []
        for cert in certificates:
            fp = cert.get("fingerprint", "")
            target_id = f"cert:{fp[:16]}"
            alg = cert.get("canonical_algorithm", "")
            q_status = cert.get("quantum_status", "UNKNOWN")
            key_size = cert.get("key_size_bits", 2048) or 2048

            # Baseline heuristic: Smaller key size / weak crypto sorted first, regardless of blast radius
            if q_status == "VULNERABLE":
                if "RSA" in alg:
                    base_score = 90.0 if key_size <= 2048 else 80.0
                elif "ECDSA" in alg or "Ed25519" in alg:
                    base_score = 85.0
                else:
                    base_score = 75.0
            elif q_status == "QUANTUM_RESISTANT":
                base_score = 15.0
            else:
                base_score = 50.0

            ranked.append({
                "target_id": target_id,
                "fingerprint": fp,
                "subject": cert.get("subject", ""),
                "canonical_algorithm": alg,
                "quantum_status": q_status,
                "baseline_score": base_score,
            })

        # Sort descending by flat baseline score
        ranked.sort(key=lambda x: (x["baseline_score"], x["target_id"]), reverse=True)

        for rank, item in enumerate(ranked):
            item["baseline_rank"] = rank + 1

        return ranked
