"""
Unit tests for QuantumRiskEngine factor evaluation, edge cases, and scanner integration.
"""
import pytest
from pathlib import Path

from signchain.risk import QuantumRiskEngine, DEFAULT_WEIGHTS, MODEL_DISCLAIMER
from signchain.scanners.x509_scanner import X509Scanner
from tests.fixtures.certs import generate_rsa_certificate


def test_low_risk_evaluation():
    engine = QuantumRiskEngine()
    result = engine.evaluate_risk(
        cryptographic_risk=0.0,  # Quantum Resistant (e.g. ML-DSA)
        asset_criticality=20.0,
        exposure=10.0,
        validity_horizon=10.0,
        dependency_impact=10.0,
        migration_complexity=10.0,
    )
    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 40.0
    assert result["contributions"]["cryptographic_risk"] == 0.0
    assert MODEL_DISCLAIMER in result["disclaimer"]


def test_high_risk_evaluation():
    engine = QuantumRiskEngine()
    result = engine.evaluate_risk(
        cryptographic_risk=90.0,  # RSA-2048
        asset_criticality=70.0,
        exposure=60.0,
        validity_horizon=50.0,
        dependency_impact=50.0,
        migration_complexity=40.0,
    )
    assert result["risk_level"] == "HIGH"
    assert 60.0 <= result["risk_score"] < 80.0
    assert "Sum =" in result["explanation"]


def test_critical_risk_evaluation():
    engine = QuantumRiskEngine()
    result = engine.evaluate_risk(
        cryptographic_risk=100.0,  # RSA-1024 / WEAK_CLASSICAL
        asset_criticality=95.0,
        exposure=90.0,
        validity_horizon=90.0,
        dependency_impact=80.0,
        migration_complexity=80.0,
    )
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 80.0


def test_boundary_values_zero_and_max():
    engine = QuantumRiskEngine()

    # Minimum boundary
    min_res = engine.evaluate_risk(
        cryptographic_risk=0.0,
        asset_criticality=0.0,
        exposure=0.0,
        validity_horizon=0.0,
        dependency_impact=0.0,
        migration_complexity=0.0,
    )
    assert min_res["risk_score"] == 0.0
    assert min_res["risk_level"] == "LOW"

    # Maximum boundary
    max_res = engine.evaluate_risk(
        cryptographic_risk=100.0,
        asset_criticality=100.0,
        exposure=100.0,
        validity_horizon=100.0,
        dependency_impact=100.0,
        migration_complexity=100.0,
    )
    assert max_res["risk_score"] == 100.0
    assert max_res["risk_level"] == "CRITICAL"


def test_invalid_factor_out_of_bounds():
    engine = QuantumRiskEngine()
    with pytest.raises(ValueError, match="out of bounds"):
        engine.evaluate_risk(cryptographic_risk=150.0)

    with pytest.raises(ValueError, match="out of bounds"):
        engine.evaluate_risk(cryptographic_risk=-10.0)


def test_invalid_weights_sum_not_one():
    invalid_weights = dict(DEFAULT_WEIGHTS)
    invalid_weights["w_crypto"] = 0.80  # Total sum will exceed 1.0

    with pytest.raises(ValueError, match="Weights must sum to 1.0"):
        QuantumRiskEngine(weights=invalid_weights)


def test_invalid_negative_weight():
    invalid_weights = dict(DEFAULT_WEIGHTS)
    invalid_weights["w_crypto"] = -0.10
    invalid_weights["w_criticality"] = 0.60

    with pytest.raises(ValueError, match="cannot be negative"):
        QuantumRiskEngine(weights=invalid_weights)


def test_invalid_missing_weight_key():
    with pytest.raises(ValueError, match="Missing keys"):
        QuantumRiskEngine(weights={"w_crypto": 1.0})


def test_scanner_risk_integration(tmp_path: Path):
    pem_bytes, _ = generate_rsa_certificate(2048)
    cert_path = tmp_path / "rsa2048.pem"
    cert_path.write_bytes(pem_bytes)

    scanner = X509Scanner()
    res = scanner.scan(str(cert_path))

    assert res["status"] == "SUCCESS"
    cert = res["certificates"][0]

    assert "risk_score" in cert
    assert cert["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL", "LOW")
    assert cert["risk_breakdown"]["cryptographic_risk"] == 27.0  # 90.0 * 0.30
    assert MODEL_DISCLAIMER in cert["risk_disclaimer"]
