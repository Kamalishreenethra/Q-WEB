"""
Unit tests for X509Scanner plugin and CLI scan command.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.scanners.x509_scanner import X509Scanner
from signchain.cli.main import app
from tests.fixtures.certs import (
    generate_rsa_certificate,
    generate_ecdsa_certificate,
    generate_ed25519_certificate,
)

runner = CliRunner()


@pytest.fixture
def rsa_pem_cert_file(tmp_path: Path) -> Path:
    pem_bytes, _ = generate_rsa_certificate(key_size=2048, is_ca=True)
    cert_path = tmp_path / "rsa_test.pem"
    cert_path.write_bytes(pem_bytes)
    return cert_path


@pytest.fixture
def rsa_der_cert_file(tmp_path: Path) -> Path:
    _, der_bytes = generate_rsa_certificate(key_size=2048)
    cert_path = tmp_path / "rsa_test.der"
    cert_path.write_bytes(der_bytes)
    return cert_path


@pytest.fixture
def ecdsa_pem_cert_file(tmp_path: Path) -> Path:
    pem_bytes, _ = generate_ecdsa_certificate()
    cert_path = tmp_path / "ecdsa_test.crt"
    cert_path.write_bytes(pem_bytes)
    return cert_path


@pytest.fixture
def ed25519_pem_cert_file(tmp_path: Path) -> Path:
    pem_bytes, _ = generate_ed25519_certificate()
    cert_path = tmp_path / "ed25519_test.pem"
    cert_path.write_bytes(pem_bytes)
    return cert_path


@pytest.fixture
def malformed_cert_file(tmp_path: Path) -> Path:
    cert_path = tmp_path / "corrupted.pem"
    cert_path.write_bytes(b"-----BEGIN CERTIFICATE-----\nNOT_BASE64_CORRUPTED_BYTES\n-----END CERTIFICATE-----")
    return cert_path


@pytest.fixture
def empty_cert_file(tmp_path: Path) -> Path:
    cert_path = tmp_path / "empty.pem"
    cert_path.write_bytes(b"")
    return cert_path


def test_can_handle(rsa_pem_cert_file: Path, rsa_der_cert_file: Path, tmp_path: Path):
    scanner = X509Scanner()
    assert scanner.can_handle(str(rsa_pem_cert_file)) is True
    assert scanner.can_handle(str(rsa_der_cert_file)) is True
    assert scanner.can_handle("non_existent_file.pem") is False

    non_cert = tmp_path / "plain.txt"
    non_cert.write_text("Hello World")
    assert scanner.can_handle(str(non_cert)) is False


def test_scan_rsa_pem_certificate(rsa_pem_cert_file: Path):
    scanner = X509Scanner()
    result = scanner.scan(str(rsa_pem_cert_file))

    assert result["status"] == "SUCCESS"
    assert result["certificate_count"] == 1
    
    certs = result["certificates"]
    assert len(certs) == 1
    cert = certs[0]

    assert cert["public_key_algorithm"] == "RSA"
    assert cert["key_size"] == 2048
    assert cert["format"] == "X.509 (PEM)"
    assert "CN=Test RSA-2048 Cert" in cert["subject"]
    assert cert["is_ca"] is True
    assert len(cert["sha256_fingerprint"]) == 64
    assert cert["signature_algorithm"] in ("sha256WithRSAEncryption", "sha256")


def test_scan_ecdsa_der_certificate(rsa_der_cert_file: Path):
    scanner = X509Scanner()
    result = scanner.scan(str(rsa_der_cert_file))

    assert result["status"] == "SUCCESS"
    assert result["certificate_count"] == 1
    
    cert = result["certificates"][0]
    assert cert["public_key_algorithm"] == "RSA"
    assert cert["format"] == "X.509 (DER)"
    assert len(cert["sha256_fingerprint"]) == 64


def test_scan_ecdsa_pem_certificate(ecdsa_pem_cert_file: Path):
    scanner = X509Scanner()
    result = scanner.scan(str(ecdsa_pem_cert_file))

    assert result["status"] == "SUCCESS"
    cert = result["certificates"][0]
    assert cert["public_key_algorithm"] == "ECDSA"
    assert cert["key_size"] == 256
    assert cert["curve"] == "secp256r1"


def test_scan_ed25519_pem_certificate(ed25519_pem_cert_file: Path):
    scanner = X509Scanner()
    result = scanner.scan(str(ed25519_pem_cert_file))

    assert result["status"] == "SUCCESS"
    cert = result["certificates"][0]
    assert cert["public_key_algorithm"] == "Ed25519"
    assert cert["curve"] == "Ed25519"


def test_scan_malformed_certificate(malformed_cert_file: Path):
    scanner = X509Scanner()
    result = scanner.scan(str(malformed_cert_file))

    assert result["status"] == "ERROR"
    assert "Malformed" in result["error_message"] or "Failed" in result["error_message"]

    normalized = scanner.normalize_result(result)
    assert len(normalized) == 1
    assert normalized[0]["status"] == "ERROR"


def test_scan_empty_file(empty_cert_file: Path):
    scanner = X509Scanner()
    result = scanner.scan(str(empty_cert_file))

    assert result["status"] == "ERROR"
    assert "empty" in result["error_message"].lower()


def test_cli_scan_human_readable(rsa_pem_cert_file: Path):
    result = runner.invoke(app, ["scan", str(rsa_pem_cert_file)])
    assert result.exit_code == 0
    assert "SIGNCHAIN DISCOVERY SCAN" in result.stdout
    assert "RSA" in result.stdout
    assert "2048" in result.stdout
    assert "SHA-256 Fingerprint" in result.stdout


def test_cli_scan_json_output(rsa_pem_cert_file: Path):
    result = runner.invoke(app, ["scan", str(rsa_pem_cert_file), "--json"])
    assert result.exit_code == 0
    
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "SUCCESS"
    assert parsed["certificate_count"] == 1
    cert = parsed["certificates"][0]
    assert cert["public_key_algorithm"] == "RSA"
    assert cert["key_size"] == 2048


def test_cli_scan_non_existent_file():
    result = runner.invoke(app, ["scan", "non_existent_cert_12345.pem"])
    assert result.exit_code == 1


def test_cli_scan_malformed_file(malformed_cert_file: Path):
    result = runner.invoke(app, ["scan", str(malformed_cert_file)])
    assert result.exit_code == 1
