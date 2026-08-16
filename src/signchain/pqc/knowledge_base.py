"""
PQC Algorithm Knowledge Base module for SignChain.
"""
import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_PQC_ALGORITHMS = [
    {
        "name": "ML-DSA-44",
        "standard_status": "NIST FIPS 204 Standardized",
        "algorithm_family": "PQC_LATTICE",
        "signature_role": "General Purpose Code Signing (Category 1)",
        "quantum_security_position": "NIST Security Level 1 (AES-128 Equivalent)",
        "implementation_available": True,
        "migration_notes": "Recommended for general purpose code signing requiring low public key and signature overhead.",
        "compatibility_notes": "Standardized in NIST FIPS 204. Primary candidate replacement for RSA-2048 and ECDSA P-256.",
    },
    {
        "name": "ML-DSA-65",
        "standard_status": "NIST FIPS 204 Standardized",
        "algorithm_family": "PQC_LATTICE",
        "signature_role": "General Purpose Code Signing (Category 3 - Recommended)",
        "quantum_security_position": "NIST Security Level 3 (AES-192 Equivalent)",
        "implementation_available": True,
        "migration_notes": "Primary recommended post-quantum signature target for enterprise software supply chains.",
        "compatibility_notes": "High security margin with balanced key size and signature generation speed.",
    },
    {
        "name": "ML-DSA-87",
        "standard_status": "NIST FIPS 204 Standardized",
        "algorithm_family": "PQC_LATTICE",
        "signature_role": "High Security Code Signing (Category 5)",
        "quantum_security_position": "NIST Security Level 5 (AES-256 Equivalent)",
        "implementation_available": True,
        "migration_notes": "Maximum security post-quantum signature for high-consequence root CAs and master signers.",
        "compatibility_notes": "Larger public key and signature size compared to ML-DSA-65.",
    },
    {
        "name": "SLH-DSA-SHA2-128f",
        "standard_status": "NIST FIPS 205 Standardized",
        "algorithm_family": "PQC_STATELESS_HASH",
        "signature_role": "Backup / Hash-Based Code Signing",
        "quantum_security_position": "NIST Security Level 1 (AES-128 Equivalent)",
        "implementation_available": True,
        "migration_notes": "Conservative fallback scheme relying only on secure cryptographic hash functions (SHA-2).",
        "compatibility_notes": "Standardized in NIST FIPS 205. Larger signature sizes (17 KB) require storage optimization.",
    },
    {
        "name": "SLH-DSA-SHA2-256f",
        "standard_status": "NIST FIPS 205 Standardized",
        "algorithm_family": "PQC_STATELESS_HASH",
        "signature_role": "High Security Hash-Based Code Signing",
        "quantum_security_position": "NIST Security Level 5 (AES-256 Equivalent)",
        "implementation_available": True,
        "migration_notes": "Conservative fallback scheme for long-term root CA certificate signatures.",
        "compatibility_notes": "Extremely robust mathematical assumptions independent of lattice hardness.",
    },
]

# Algorithm family constants used for candidate matching
_HIGH_SECURITY_FAMILIES = {"CLASSICAL_FACTORIZATION"}
_HIGH_SECURITY_KEY_THRESHOLD = 4096
_HIGH_SECURITY_CURVES = {"P-521", "SECP521R1", "ED448"}


class PQCKnowledgeBase:
    """
    Structured knowledge base providing standardized PQC algorithm information and migration candidates.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.algorithms: List[Dict[str, Any]] = []
        self._load_knowledge_base(config_path)

    def _load_knowledge_base(self, config_path: Optional[str]) -> None:
        path_to_try = config_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
            "config",
            "pqc_algorithms.yaml",
        )

        if os.path.exists(path_to_try):
            try:
                with open(path_to_try, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "pqc_algorithms" in data:
                        self.algorithms = data["pqc_algorithms"]
                        return
            except Exception:
                pass

        # Fallback to default in-memory list
        self.algorithms = list(DEFAULT_PQC_ALGORITHMS)

    def get_algorithm(self, name: str) -> Optional[Dict[str, Any]]:
        """Returns record for a specific PQC algorithm name, or None."""
        name_u = name.upper()
        for alg in self.algorithms:
            if alg["name"].upper() == name_u:
                return dict(alg)
        return None

    def _is_high_security(self, algorithm: str, algorithm_family: Optional[str] = None) -> bool:
        """
        Determines whether a classical algorithm warrants high-security (NIST Level 5) PQC candidates.
        Uses algorithm family classification when available, falling back to algorithm name analysis.
        """
        alg_u = (algorithm or "").upper()
        fam_u = (algorithm_family or "").upper()

        # High-security ECC curves
        for curve in _HIGH_SECURITY_CURVES:
            if curve in alg_u:
                return True

        # RSA with key size >= 4096
        if "RSA" in alg_u or fam_u == "CLASSICAL_FACTORIZATION":
            # Extract key size from algorithm name like "RSA-4096"
            for part in alg_u.replace("-", " ").replace("_", " ").split():
                try:
                    key_bits = int(part)
                    if key_bits >= _HIGH_SECURITY_KEY_THRESHOLD:
                        return True
                except ValueError:
                    continue

        return False

    def get_recommended_candidates(
        self,
        classical_algorithm: str,
        algorithm_family: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns structured candidate PQC migration algorithms for a given classical algorithm.

        Candidate selection is based on algorithm family classification rather than
        brittle substring matching. High-security classical algorithms (RSA-4096, P-521,
        Ed448) map to NIST Level 5 candidates; standard-security algorithms map to
        NIST Level 3 candidates.

        Args:
            classical_algorithm: The canonical algorithm name (e.g. "RSA-2048", "ECDSA-P256").
            algorithm_family: Optional algorithm family from the classifier (e.g. "CLASSICAL_FACTORIZATION").
        """
        alg_u = (classical_algorithm or "").upper()

        # PQC/hybrid algorithms don't need migration candidates
        if "ML-DSA" in alg_u or "SLH-DSA" in alg_u or "DILITHIUM" in alg_u or "SPHINCS" in alg_u:
            return []

        if self._is_high_security(classical_algorithm, algorithm_family):
            # High-security: NIST Level 5
            primary = self.get_algorithm("ML-DSA-87") or DEFAULT_PQC_ALGORITHMS[2]
            fallback = self.get_algorithm("SLH-DSA-SHA2-256f") or DEFAULT_PQC_ALGORITHMS[4]

            primary_rec = dict(primary)
            primary_rec["recommendation_type"] = "PRIMARY"
            primary_rec["reason"] = "NIST Level 5 ML-DSA signature recommended for high-consequence keys."

            fallback_rec = dict(fallback)
            fallback_rec["recommendation_type"] = "FALLBACK"
            fallback_rec["reason"] = "NIST Level 5 stateless hash-based signature for conservative backup."
            return [primary_rec, fallback_rec]

        # Standard security: NIST Level 3
        primary = self.get_algorithm("ML-DSA-65") or DEFAULT_PQC_ALGORITHMS[1]
        fallback = self.get_algorithm("SLH-DSA-SHA2-128f") or DEFAULT_PQC_ALGORITHMS[3]

        primary_rec = dict(primary)
        primary_rec["recommendation_type"] = "PRIMARY"
        primary_rec["reason"] = "NIST Level 3 ML-DSA lattice signature recommended as primary replacement."

        fallback_rec = dict(fallback)
        fallback_rec["recommendation_type"] = "FALLBACK"
        fallback_rec["reason"] = "Stateless hash-based signature recommended as conservative backup."
        return [primary_rec, fallback_rec]
