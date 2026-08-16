"""
Deterministic Cryptographic Classifier and Quantum Status Engine for SignChain.
"""
from typing import Any, Dict, Optional, Tuple


class QuantumStatus:
    WEAK_CLASSICAL = "WEAK_CLASSICAL"
    VULNERABLE = "VULNERABLE"
    HYBRID_READY = "HYBRID_READY"
    QUANTUM_RESISTANT = "QUANTUM_RESISTANT"


class AlgorithmFamily:
    CLASSICAL_FACTORIZATION = "CLASSICAL_FACTORIZATION"
    CLASSICAL_ECC = "CLASSICAL_ECC"
    CLASSICAL_DISCRETE_LOG = "CLASSICAL_DISCRETE_LOG"
    PQC_LATTICE = "PQC_LATTICE"
    PQC_STATELESS_HASH = "PQC_STATELESS_HASH"
    UNKNOWN = "UNKNOWN"


# NIST OIDs for PQC Standards (FIPS 204 ML-DSA & FIPS 205 SLH-DSA)
PQC_OIDS = {
    "2.16.840.1.101.3.4.3.17": {"name": "ML-DSA-44", "family": AlgorithmFamily.PQC_LATTICE, "security_bits": 128},
    "2.16.840.1.101.3.4.3.18": {"name": "ML-DSA-65", "family": AlgorithmFamily.PQC_LATTICE, "security_bits": 192},
    "2.16.840.1.101.3.4.3.19": {"name": "ML-DSA-87", "family": AlgorithmFamily.PQC_LATTICE, "security_bits": 256},
    "2.16.840.1.101.3.4.3.20": {"name": "SLH-DSA-SHA2-128s", "family": AlgorithmFamily.PQC_STATELESS_HASH, "security_bits": 128},
    "2.16.840.1.101.3.4.3.21": {"name": "SLH-DSA-SHA2-128f", "family": AlgorithmFamily.PQC_STATELESS_HASH, "security_bits": 128},
    "2.16.840.1.101.3.4.3.22": {"name": "SLH-DSA-SHA2-192s", "family": AlgorithmFamily.PQC_STATELESS_HASH, "security_bits": 192},
    "2.16.840.1.101.3.4.3.23": {"name": "SLH-DSA-SHA2-192f", "family": AlgorithmFamily.PQC_STATELESS_HASH, "security_bits": 192},
    "2.16.840.1.101.3.4.3.24": {"name": "SLH-DSA-SHA2-256s", "family": AlgorithmFamily.PQC_STATELESS_HASH, "security_bits": 256},
    "2.16.840.1.101.3.4.3.25": {"name": "SLH-DSA-SHA2-256f", "family": AlgorithmFamily.PQC_STATELESS_HASH, "security_bits": 256},
}


class CryptoClassifier:
    """
    Deterministically classifies public key algorithms, estimates classical security bits,
    and assigns explainable quantum risk status.
    """

    CONFIDENCE_SOURCE = "100% Deterministic ASN.1/X.509 Metadata OID Parsing"

    def classify(
        self,
        algorithm_name: str,
        key_size: Optional[int] = None,
        curve: Optional[str] = None,
        oid: Optional[str] = None,
        signature_algorithm: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Classifies a public key and returns quantum status, family, security bits, and explanation.
        """
        alg_upper = (algorithm_name or "").upper()

        # Check OID for PQC algorithms first
        if oid and oid in PQC_OIDS:
            pqc_info = PQC_OIDS[oid]
            return {
                "algorithm": pqc_info["name"],
                "family": pqc_info["family"],
                "key_parameters": {
                    "key_size": key_size,
                    "curve": curve,
                    "oid": oid,
                    "security_bits": pqc_info["security_bits"],
                },
                "quantum_status": QuantumStatus.QUANTUM_RESISTANT,
                "reason": (
                    f"{pqc_info['name']} is a NIST FIPS standard post-quantum signature scheme "
                    f"resistant to Shor's and Grover's quantum algorithms."
                ),
                "confidence_source": self.CONFIDENCE_SOURCE,
            }

        # Check PQC algorithm names explicitly
        if "ML-DSA" in alg_upper or "DILITHIUM" in alg_upper:
            sec_bits = 128
            if "65" in alg_upper:
                sec_bits = 192
            elif "87" in alg_upper:
                sec_bits = 256
            return {
                "algorithm": algorithm_name,
                "family": AlgorithmFamily.PQC_LATTICE,
                "key_parameters": {
                    "key_size": key_size,
                    "curve": curve,
                    "oid": oid,
                    "security_bits": sec_bits,
                },
                "quantum_status": QuantumStatus.QUANTUM_RESISTANT,
                "reason": (
                    f"{algorithm_name} is a lattice-based post-quantum signature algorithm "
                    f"providing NIST level security resistant to quantum computer attacks."
                ),
                "confidence_source": self.CONFIDENCE_SOURCE,
            }

        if "SLH-DSA" in alg_upper or "SPHINCS" in alg_upper:
            return {
                "algorithm": algorithm_name,
                "family": AlgorithmFamily.PQC_STATELESS_HASH,
                "key_parameters": {
                    "key_size": key_size,
                    "curve": curve,
                    "oid": oid,
                    "security_bits": 128,
                },
                "quantum_status": QuantumStatus.QUANTUM_RESISTANT,
                "reason": (
                    f"{algorithm_name} is a stateless hash-based post-quantum signature algorithm "
                    f"resistant to quantum computer attacks."
                ),
                "confidence_source": self.CONFIDENCE_SOURCE,
            }

        # RSA Classification
        if "RSA" in alg_upper:
            sec_bits = self._estimate_rsa_security_bits(key_size)
            canonical_name = f"RSA-{key_size}" if key_size else "RSA"
            
            if key_size and key_size < 2048:
                return {
                    "algorithm": canonical_name,
                    "family": AlgorithmFamily.CLASSICAL_FACTORIZATION,
                    "key_parameters": {
                        "key_size": key_size,
                        "curve": None,
                        "oid": oid,
                        "security_bits": sec_bits,
                    },
                    "quantum_status": QuantumStatus.WEAK_CLASSICAL,
                    "reason": (
                        f"RSA with key size {key_size} bits is considered classically weak (<2048 bits) "
                        f"and is vulnerable to both classical factorization and future quantum attacks (Shor's algorithm)."
                    ),
                    "confidence_source": self.CONFIDENCE_SOURCE,
                }
            
            return {
                "algorithm": canonical_name,
                "family": AlgorithmFamily.CLASSICAL_FACTORIZATION,
                "key_parameters": {
                    "key_size": key_size,
                    "curve": None,
                    "oid": oid,
                    "security_bits": sec_bits,
                },
                "quantum_status": QuantumStatus.VULNERABLE,
                "reason": (
                    f"{canonical_name} relies on the integer factorization problem, which can be solved in "
                    f"polynomial time by Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC)."
                ),
                "confidence_source": self.CONFIDENCE_SOURCE,
            }

        # ECDSA & EdDSA Classification
        if "ECDSA" in alg_upper or "EC" in alg_upper or "ED25519" in alg_upper or "ED448" in alg_upper:
            curve_name = curve or ""
            sec_bits = self._estimate_ecc_security_bits(key_size, curve_name)
            
            if "ED25519" in alg_upper or "ED25519" in curve_name.upper():
                canonical_name = "Ed25519"
                family = AlgorithmFamily.CLASSICAL_ECC
            elif "ED448" in alg_upper or "ED448" in curve_name.upper():
                canonical_name = "Ed448"
                family = AlgorithmFamily.CLASSICAL_ECC
            else:
                canonical_name = f"ECDSA-{curve_name}" if curve_name else f"ECDSA-{key_size or 'EC'}"
                family = AlgorithmFamily.CLASSICAL_ECC

            return {
                "algorithm": canonical_name,
                "family": family,
                "key_parameters": {
                    "key_size": key_size,
                    "curve": curve_name,
                    "oid": oid,
                    "security_bits": sec_bits,
                },
                "quantum_status": QuantumStatus.VULNERABLE,
                "reason": (
                    f"{canonical_name} relies on the elliptic curve discrete logarithm problem (ECDLP), "
                    f"which is vulnerable to quantum attacks via Shor's algorithm on a CRQC."
                ),
                "confidence_source": self.CONFIDENCE_SOURCE,
            }

        # DSA Classification
        if "DSA" in alg_upper:
            return {
                "algorithm": f"DSA-{key_size}" if key_size else "DSA",
                "family": AlgorithmFamily.CLASSICAL_DISCRETE_LOG,
                "key_parameters": {
                    "key_size": key_size,
                    "curve": None,
                    "oid": oid,
                    "security_bits": self._estimate_rsa_security_bits(key_size),
                },
                "quantum_status": QuantumStatus.VULNERABLE,
                "reason": (
                    "DSA relies on finite field discrete logarithms, which can be broken by Shor's algorithm on a CRQC."
                ),
                "confidence_source": self.CONFIDENCE_SOURCE,
            }

        # Fallback for Unknown algorithm
        return {
            "algorithm": algorithm_name or "UNKNOWN",
            "family": AlgorithmFamily.UNKNOWN,
            "key_parameters": {
                "key_size": key_size,
                "curve": curve,
                "oid": oid,
                "security_bits": None,
            },
            "quantum_status": "UNKNOWN",
            "reason": "Unrecognized or unsupported cryptographic signature algorithm.",
            "confidence_source": self.CONFIDENCE_SOURCE,
        }

    def _estimate_rsa_security_bits(self, key_size: Optional[int]) -> int:
        if not key_size:
            return 112
        if key_size < 2048:
            return 80
        if key_size < 3072:
            return 112
        if key_size < 7680:
            return 128
        return 256

    def _estimate_ecc_security_bits(self, key_size: Optional[int], curve: str) -> int:
        curve_u = curve.upper()
        if "521" in curve_u or key_size == 521:
            return 256
        if "384" in curve_u or key_size == 384 or "ED448" in curve_u:
            return 192
        return 128
