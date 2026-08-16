"""
Unit tests for CryptoClassifier and quantum status engine.
"""
import pytest
from pathlib import Path

from signchain.classifiers import CryptoClassifier, QuantumStatus, AlgorithmFamily
from signchain.scanners.x509_scanner import X509Scanner
from tests.fixtures.certs import (
    generate_rsa_certificate,
    generate_ecdsa_certificate,
    generate_ed25519_certificate,
)


def test_classify_rsa_1024_weak_classical():
    classifier = CryptoClassifier()
    res = classifier.classify("RSA", key_size=1024)

    assert res["algorithm"] == "RSA-1024"
    assert res["family"] == AlgorithmFamily.CLASSICAL_FACTORIZATION
    assert res["quantum_status"] == QuantumStatus.WEAK_CLASSICAL
    assert res["key_parameters"]["security_bits"] == 80
    assert "classically weak" in res["reason"]
    assert "100% Deterministic" in res["confidence_source"]


def test_classify_rsa_2048_vulnerable():
    classifier = CryptoClassifier()
    res = classifier.classify("RSA", key_size=2048)

    assert res["algorithm"] == "RSA-2048"
    assert res["family"] == AlgorithmFamily.CLASSICAL_FACTORIZATION
    assert res["quantum_status"] == QuantumStatus.VULNERABLE
    assert res["key_parameters"]["security_bits"] == 112
    assert "Shor's algorithm" in res["reason"]


def test_classify_ecdsa_p256_vulnerable():
    classifier = CryptoClassifier()
    res = classifier.classify("ECDSA", key_size=256, curve="secp256r1")

    assert res["family"] == AlgorithmFamily.CLASSICAL_ECC
    assert res["quantum_status"] == QuantumStatus.VULNERABLE
    assert res["key_parameters"]["security_bits"] == 128
    assert "elliptic curve discrete logarithm" in res["reason"]


def test_classify_ed25519_vulnerable():
    classifier = CryptoClassifier()
    res = classifier.classify("Ed25519", curve="Ed25519")

    assert res["algorithm"] == "Ed25519"
    assert res["family"] == AlgorithmFamily.CLASSICAL_ECC
    assert res["quantum_status"] == QuantumStatus.VULNERABLE
    assert res["key_parameters"]["security_bits"] == 128


def test_classify_ml_dsa_44_quantum_resistant():
    classifier = CryptoClassifier()
    res = classifier.classify("ML-DSA-44", oid="2.16.840.1.101.3.4.3.17")

    assert res["algorithm"] == "ML-DSA-44"
    assert res["family"] == AlgorithmFamily.PQC_LATTICE
    assert res["quantum_status"] == QuantumStatus.QUANTUM_RESISTANT
    assert res["key_parameters"]["security_bits"] == 128
    assert "NIST FIPS standard" in res["reason"]


def test_classify_ml_dsa_65_quantum_resistant():
    classifier = CryptoClassifier()
    res = classifier.classify("ML-DSA-65", oid="2.16.840.1.101.3.4.3.18")

    assert res["algorithm"] == "ML-DSA-65"
    assert res["family"] == AlgorithmFamily.PQC_LATTICE
    assert res["quantum_status"] == QuantumStatus.QUANTUM_RESISTANT
    assert res["key_parameters"]["security_bits"] == 192


def test_classify_ml_dsa_87_quantum_resistant():
    classifier = CryptoClassifier()
    res = classifier.classify("ML-DSA-87", oid="2.16.840.1.101.3.4.3.19")

    assert res["algorithm"] == "ML-DSA-87"
    assert res["family"] == AlgorithmFamily.PQC_LATTICE
    assert res["quantum_status"] == QuantumStatus.QUANTUM_RESISTANT
    assert res["key_parameters"]["security_bits"] == 256


def test_classify_slh_dsa_quantum_resistant():
    classifier = CryptoClassifier()
    res = classifier.classify("SLH-DSA-SHA2-128f", oid="2.16.840.1.101.3.4.3.21")

    assert res["algorithm"] == "SLH-DSA-SHA2-128f"
    assert res["family"] == AlgorithmFamily.PQC_STATELESS_HASH
    assert res["quantum_status"] == QuantumStatus.QUANTUM_RESISTANT


def test_x509_scanner_classifier_integration(tmp_path: Path):
    pem_bytes, _ = generate_rsa_certificate(key_size=2048)
    cert_path = tmp_path / "integration_cert.pem"
    cert_path.write_bytes(pem_bytes)

    scanner = X509Scanner()
    result = scanner.scan(str(cert_path))

    assert result["status"] == "SUCCESS"
    cert = result["certificates"][0]
    
    assert cert["quantum_status"] == QuantumStatus.VULNERABLE
    assert cert["canonical_algorithm"] == "RSA-2048"
    assert cert["algorithm_family"] == AlgorithmFamily.CLASSICAL_FACTORIZATION
    assert cert["classical_security_bits"] == 112
    assert "Shor's algorithm" in cert["quantum_reason"]
    assert "100% Deterministic" in cert["confidence_source"]
