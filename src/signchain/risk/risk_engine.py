"""
Transparent Quantum Risk Engine for SignChain.
"""
from typing import Any, Dict, Optional

DEFAULT_WEIGHTS = {
    "w_crypto": 0.30,
    "w_criticality": 0.20,
    "w_exposure": 0.15,
    "w_horizon": 0.15,
    "w_dependency": 0.10,
    "w_complexity": 0.10,
}

MODEL_DISCLAIMER = (
    "Transparent heuristic risk model — weights are organizational policy parameters under experimental evaluation. "
    "Not a scientifically validated risk probability metric."
)


class QuantumRiskEngine:
    """
    Computes explainable, transparent quantum risk scores for software supply chain artifacts.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize the risk engine with configurable weights.
        """
        self.weights = weights if weights is not None else dict(DEFAULT_WEIGHTS)
        self._validate_weights(self.weights)

    def _validate_weights(self, weights: Dict[str, float]) -> None:
        required_keys = {"w_crypto", "w_criticality", "w_exposure", "w_horizon", "w_dependency", "w_complexity"}
        if set(weights.keys()) != required_keys:
            missing = required_keys - set(weights.keys())
            raise ValueError(f"Invalid weights config. Missing keys: {missing}")

        for k, v in weights.items():
            if not isinstance(v, (int, float)):
                raise ValueError(f"Weight '{k}' must be a numeric value, got {type(v).__name__}.")
            if v < 0.0:
                raise ValueError(f"Weight '{k}' cannot be negative ({v}).")

        total_weight = sum(weights.values())
        if abs(total_weight - 1.0) > 1e-4:
            raise ValueError(f"Weights must sum to 1.0, got total sum of {total_weight:.4f}.")

    def evaluate_risk(
        self,
        cryptographic_risk: float,
        asset_criticality: float = 50.0,
        exposure: float = 50.0,
        validity_horizon: float = 50.0,
        dependency_impact: float = 50.0,
        migration_complexity: float = 50.0,
        custom_weights: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates risk score and returns a full, explainable calculation breakdown.
        """
        weights = custom_weights if custom_weights is not None else self.weights
        self._validate_weights(weights)

        factors = {
            "cryptographic_risk": cryptographic_risk,
            "asset_criticality": asset_criticality,
            "exposure": exposure,
            "validity_horizon": validity_horizon,
            "dependency_impact": dependency_impact,
            "migration_complexity": migration_complexity,
        }

        # Validate factor bounds [0, 100]
        for fname, val in factors.items():
            if not isinstance(val, (int, float)):
                raise ValueError(f"Factor '{fname}' must be numeric, got {type(val).__name__}.")
            if val < 0.0 or val > 100.0:
                raise ValueError(f"Factor '{fname}' out of bounds [0, 100]: got {val}.")

        # Weighted calculation
        c_contrib = factors["cryptographic_risk"] * weights["w_crypto"]
        a_contrib = factors["asset_criticality"] * weights["w_criticality"]
        e_contrib = factors["exposure"] * weights["w_exposure"]
        h_contrib = factors["validity_horizon"] * weights["w_horizon"]
        d_contrib = factors["dependency_impact"] * weights["w_dependency"]
        m_contrib = factors["migration_complexity"] * weights["w_complexity"]

        raw_score = c_contrib + a_contrib + e_contrib + h_contrib + d_contrib + m_contrib
        score = round(raw_score, 2)
        score_int = round(raw_score)

        if score_int >= 80:
            level = "CRITICAL"
        elif score_int >= 60:
            level = "HIGH"
        elif score_int >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Generate transparent explanation
        explanation = (
            f"Quantum Risk Score: {score}/100 ({level})\n"
            f"Formula: Score = w_c*R_crypto + w_a*C_asset + w_e*E_exposure + w_h*H_horizon + w_d*I_dep + w_m*M_complexity\n"
            f"Component Breakdown:\n"
            f"  - Cryptographic Risk : {factors['cryptographic_risk']:.1f} * {weights['w_crypto']:.2f} = {c_contrib:.2f}\n"
            f"  - Asset Criticality  : {factors['asset_criticality']:.1f} * {weights['w_criticality']:.2f} = {a_contrib:.2f}\n"
            f"  - Exposure Level     : {factors['exposure']:.1f} * {weights['w_exposure']:.2f} = {e_contrib:.2f}\n"
            f"  - Validity Horizon   : {factors['validity_horizon']:.1f} * {weights['w_horizon']:.2f} = {h_contrib:.2f}\n"
            f"  - Dependency Impact  : {factors['dependency_impact']:.1f} * {weights['w_dependency']:.2f} = {d_contrib:.2f}\n"
            f"  - Migration Complexity: {factors['migration_complexity']:.1f} * {weights['w_complexity']:.2f} = {m_contrib:.2f}\n"
            f"Sum = {score:.2f} -> Risk Tier: {level}"
        )

        return {
            "risk_score": score,
            "risk_score_int": score_int,
            "risk_level": level,
            "factors": factors,
            "weights": weights,
            "contributions": {
                "cryptographic_risk": round(c_contrib, 2),
                "asset_criticality": round(a_contrib, 2),
                "exposure": round(e_contrib, 2),
                "validity_horizon": round(h_contrib, 2),
                "dependency_impact": round(d_contrib, 2),
                "migration_complexity": round(m_contrib, 2),
            },
            "explanation": explanation,
            "disclaimer": MODEL_DISCLAIMER,
        }

    @staticmethod
    def map_crypto_risk_score(quantum_status: str, canonical_algorithm: str) -> float:
        """
        Maps deterministic quantum status and algorithm family to default 0-100 crypto risk score.
        """
        status_upper = (quantum_status or "").upper()
        alg_upper = (canonical_algorithm or "").upper()

        if status_upper == "QUANTUM_RESISTANT":
            return 0.0
        if status_upper == "HYBRID_READY":
            return 25.0
        if status_upper == "WEAK_CLASSICAL":
            return 100.0

        if "RSA-1024" in alg_upper:
            return 100.0
        if "RSA-2048" in alg_upper:
            return 90.0
        if "ECDSA" in alg_upper or "ED25519" in alg_upper:
            return 85.0
        if "RSA-3072" in alg_upper:
            return 80.0
        if "RSA-4096" in alg_upper:
            return 70.0

        return 85.0

    @staticmethod
    def normalize_dependency_impact(downstream_count: int, max_expected_count: float = 50.0) -> float:
        """
        Transparently normalizes raw downstream dependency reachability count into a 0-100 score.
        Uses logarithmic scaling to reflect diminishing marginal risk increase for additional downstream assets.
        Formula: Score = min(100.0, ln(1 + count) / ln(1 + max_expected) * 100.0)
        """
        import math
        if downstream_count <= 0:
            return 0.0

        target_max = max(1.0, max_expected_count)
        log_count = math.log(1.0 + downstream_count)
        log_max = math.log(1.0 + target_max)

        score = (log_count / log_max) * 100.0
        return round(min(100.0, max(0.0, score)), 2)
