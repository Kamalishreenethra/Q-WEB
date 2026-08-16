"""
Abstract base scanner interface for SignChain artifact discovery plugins.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseScanner(ABC):
    """
    Abstract base class for all artifact signature scanners.
    
    Every scanner plugin MUST implement can_handle(), scan(), and normalize_result().
    """

    @abstractmethod
    def can_handle(self, file_path: str) -> bool:
        """
        Determines whether this scanner plugin can process the given artifact.
        
        Args:
            file_path: Path to the target file artifact.
            
        Returns:
            True if this scanner plugin can process the file, False otherwise.
        """
        pass

    @abstractmethod
    def scan(self, file_path: str) -> Dict[str, Any]:
        """
        Scans the target file artifact and extracts raw cryptographic signature data.
        
        Args:
            file_path: Path to the target file artifact.
            
        Returns:
            A dictionary containing raw extracted signature metadata or error details.
        """
        pass

    @abstractmethod
    def normalize_result(self, raw_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalizes raw scanner output into standardized SignChain schema dictionaries.
        
        Args:
            raw_result: The raw dictionary returned by scan().
            
        Returns:
            A list of normalized signature record dictionaries.
        """
        pass


def extract_public_key_details(cert: Any) -> Dict[str, Any]:
    """
    Extracts public key algorithm, key size in bits, and elliptic curve parameters
    from a cryptography X.509 Certificate object.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

    try:
        pub_key = cert.public_key()
    except Exception as e:
        return {"algorithm": "UNKNOWN", "error": str(e)}

    if isinstance(pub_key, rsa.RSAPublicKey):
        return {
            "algorithm": "RSA",
            "key_size": pub_key.key_size,
        }
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return {
            "algorithm": "ECDSA",
            "key_size": pub_key.key_size,
            "curve": pub_key.curve.name,
        }
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        return {
            "algorithm": "Ed25519",
            "key_size": 256,
            "curve": "Ed25519",
        }
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        return {
            "algorithm": "Ed448",
            "key_size": 448,
            "curve": "Ed448",
        }
    elif isinstance(pub_key, dsa.DSAPublicKey):
        return {
            "algorithm": "DSA",
            "key_size": pub_key.key_size,
        }
    else:
        alg_name = pub_key.__class__.__name__.replace("PublicKey", "").upper()
        return {
            "algorithm": alg_name or "UNKNOWN",
            "key_size": getattr(pub_key, "key_size", None),
        }


def extract_certificate_metadata(
    cert: Any,
    file_path: str,
    format_label: str,
    index: int = 0,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Standardized, shared extraction of normalized cryptographic fields, deterministic quantum classification,
    and quantum risk evaluation from an X.509 Certificate object.
    """
    import os
    from datetime import timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from signchain.classifiers.crypto_classifier import CryptoClassifier
    from signchain.risk.risk_engine import QuantumRiskEngine

    # Dates UTC format
    if hasattr(cert, "not_valid_before_utc"):
        not_before = cert.not_valid_before_utc.isoformat()
    else:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()

    if hasattr(cert, "not_valid_after_utc"):
        not_after = cert.not_valid_after_utc.isoformat()
    else:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

    # Subject & Issuer RFC4514 strings
    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()

    # Serial number
    serial_int = cert.serial_number
    serial_hex = f"{serial_int:X}"
    if len(serial_hex) % 2 != 0:
        serial_hex = "0" + serial_hex

    # SHA-256 Fingerprint
    sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex().lower()

    # Signature Algorithm OID & Name
    sig_alg_name = cert.signature_algorithm_oid._name
    if sig_alg_name == "unknown":
        sig_alg_name = cert.signature_algorithm_oid.dotted_string

    # Public key details
    pub_key_info = extract_public_key_details(cert)

    # Deterministic Cryptographic Classification
    classifier = CryptoClassifier()
    classification = classifier.classify(
        algorithm_name=pub_key_info["algorithm"],
        key_size=pub_key_info.get("key_size"),
        curve=pub_key_info.get("curve"),
        oid=pub_key_info.get("oid"),
        signature_algorithm=sig_alg_name,
    )

    # Transparent Quantum Risk Evaluation
    risk_engine = QuantumRiskEngine()
    crypto_risk_score = QuantumRiskEngine.map_crypto_risk_score(
        quantum_status=classification["quantum_status"],
        canonical_algorithm=classification["algorithm"],
    )
    risk_assessment = risk_engine.evaluate_risk(
        cryptographic_risk=crypto_risk_score,
        asset_criticality=50.0,
        exposure=50.0,
        validity_horizon=50.0,
        dependency_impact=50.0,
        migration_complexity=50.0,
    )

    # Basic Constraints / CA status
    is_ca = False
    try:
        ext = cert.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
        is_ca = ext.value.ca
    except Exception:
        pass

    record = {
        "status": "SUCCESS",
        "artifact_name": os.path.basename(file_path),
        "file_path": file_path,
        "certificate_index": index,
        "format": format_label,
        "subject": subject_str,
        "issuer": issuer_str,
        "serial_number": serial_hex,
        "serial_number_int": serial_int,
        "not_before": not_before,
        "not_after": not_after,
        "public_key_algorithm": pub_key_info["algorithm"],
        "canonical_algorithm": classification["algorithm"],
        "algorithm_family": classification["family"],
        "classical_security_bits": classification["key_parameters"]["security_bits"],
        "quantum_status": classification["quantum_status"],
        "quantum_reason": classification["reason"],
        "confidence_source": classification["confidence_source"],
        "risk_score": risk_assessment["risk_score"],
        "risk_level": risk_assessment["risk_level"],
        "risk_breakdown": risk_assessment["contributions"],
        "risk_explanation": risk_assessment["explanation"],
        "risk_disclaimer": risk_assessment["disclaimer"],
        "key_size": pub_key_info.get("key_size"),
        "curve": pub_key_info.get("curve"),
        "signature_algorithm": sig_alg_name,
        "sha256_fingerprint": sha256_fingerprint,
        "is_ca": is_ca,
    }

    if extra_fields:
        record.update(extra_fields)

    return record

