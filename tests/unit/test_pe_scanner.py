"""
Unit tests for PEScanner, Authenticode discovery, certificate extraction, and CLI integration.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.scanners.pe_scanner import PEScanner
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine
from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType
from signchain.pqc.readiness_engine import PQCReadinessEngine, ReadinessState
from signchain.migration.migration_engine import MigrationPrioritizationEngine
from signchain.cli.main import app
from tests.fixtures.certs import generate_rsa_certificate, generate_ecdsa_certificate
from tests.fixtures.pe import generate_unsigned_pe_file, generate_signed_pe_file

runner = CliRunner()


def test_can_handle_pe_files(tmp_path: Path):
    scanner = PEScanner()

    # Valid extensions
    for ext in [".exe", ".dll", ".sys", ".ocx", ".efi"]:
        f = tmp_path / f"test{ext}"
        f.write_bytes(generate_unsigned_pe_file())
        assert scanner.can_handle(str(f)) is True

    # Non-PE file
    txt_file = tmp_path / "test.txt"
    txt_file.write_text("Hello World")
    assert scanner.can_handle(str(txt_file)) is False

    # Non-existent file
    assert scanner.can_handle(str(tmp_path / "missing.exe")) is False


def test_scan_unsigned_pe_file(tmp_path: Path):
    pe_file = tmp_path / "unsigned_app.exe"
    pe_file.write_bytes(generate_unsigned_pe_file(is_64bit=True))

    scanner = PEScanner()
    res = scanner.scan(str(pe_file))

    assert res["status"] == "SUCCESS"
    assert res["authenticode_status"] == "UNSIGNED"
    assert res["pe_format"] == "PE32+"
    assert res["architecture"] == "x86-64 (64-bit)"
    assert res["certificate_count"] == 0
    assert len(res["certificates"]) == 0

    norm = scanner.normalize_result(res)
    assert len(norm) == 1
    assert norm[0]["authenticode_status"] == "UNSIGNED"
    assert norm[0]["quantum_status"] == "NOT_APPLICABLE"
    assert norm[0]["risk_score"] == 0.0


def test_scan_signed_rsa_pe_file(tmp_path: Path):
    _, der_cert = generate_rsa_certificate(key_size=2048)
    pe_file = tmp_path / "signed_rsa.exe"
    pe_file.write_bytes(generate_signed_pe_file([der_cert], is_64bit=True))

    scanner = PEScanner()
    res = scanner.scan(str(pe_file))

    assert res["status"] == "SUCCESS"
    assert res["authenticode_status"] == "SIGNED"
    assert res["certificate_count"] == 1

    cert = res["certificates"][0]
    assert cert["public_key_algorithm"] == "RSA"
    assert cert["canonical_algorithm"] == "RSA-2048"
    assert cert["key_size"] == 2048
    assert cert["quantum_status"] == "VULNERABLE"
    assert cert["risk_score"] >= 60.0
    assert "SignChain Test Org" in cert["subject"]
    assert "SignChain Test Org" in cert["issuer"]

    norm = scanner.normalize_result(res)
    assert len(norm) == 1
    assert norm[0]["canonical_algorithm"] == "RSA-2048"


def test_scan_signed_ecdsa_pe_file(tmp_path: Path):
    _, der_cert = generate_ecdsa_certificate()
    pe_file = tmp_path / "signed_ecdsa.dll"
    pe_file.write_bytes(generate_signed_pe_file([der_cert], is_64bit=True))

    scanner = PEScanner()
    res = scanner.scan(str(pe_file))

    assert res["status"] == "SUCCESS"
    assert res["authenticode_status"] == "SIGNED"
    assert res["certificate_count"] == 1

    cert = res["certificates"][0]
    assert cert["public_key_algorithm"] == "ECDSA"
    assert cert["curve"] in ("secp256r1", "prime256v1", "P-256")
    assert cert["quantum_status"] == "VULNERABLE"


def test_scan_signed_pe32_file(tmp_path: Path):
    _, der_cert = generate_rsa_certificate(key_size=2048)
    pe_file = tmp_path / "signed_32bit.exe"
    pe_file.write_bytes(generate_signed_pe_file([der_cert], is_64bit=False))

    scanner = PEScanner()
    res = scanner.scan(str(pe_file))

    assert res["status"] == "SUCCESS"
    assert res["pe_format"] == "PE32"
    assert res["architecture"] == "x86 (32-bit)"
    assert res["authenticode_status"] == "SIGNED"
    assert res["certificate_count"] == 1


def test_scan_malformed_pe_file(tmp_path: Path):
    malformed = tmp_path / "broken.exe"
    malformed.write_bytes(b"MZ" + b"\x00" * 30 + b"RANDOM_CORRUPTED_BYTES")

    scanner = PEScanner()
    res = scanner.scan(str(malformed))

    assert res["status"] == "ERROR"
    assert "error_message" in res
    assert "file_path" in res


def test_scan_corrupted_security_directory(tmp_path: Path):
    # Valid PE with security directory pointing out of file bounds
    pe_bytes = bytearray(generate_unsigned_pe_file())
    # Modify security directory offset (data_dirs starts after headers)
    # Put an invalid offset 0xFFFFFF into security data dir
    import struct
    # Security directory is at offset (64 + 4 + 20 + 112 + 4*8) = 232
    struct.pack_into("<II", pe_bytes, 232, 0x10000, 0x500)

    broken_sec = tmp_path / "broken_security.exe"
    broken_sec.write_bytes(pe_bytes)

    scanner = PEScanner()
    res = scanner.scan(str(broken_sec))

    assert res["status"] == "ERROR"
    assert "Corrupted Authenticode" in res["error_message"]


def test_scan_oversized_file(tmp_path: Path):
    pe_file = tmp_path / "large.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 200)

    # Max size = 100 bytes
    scanner = PEScanner(max_file_size=100)
    res = scanner.scan(str(pe_file))

    assert res["status"] == "ERROR"
    assert "exceeds maximum allowed size" in res["error_message"]


def test_scan_empty_file(tmp_path: Path):
    empty_file = tmp_path / "empty.exe"
    empty_file.write_bytes(b"")

    scanner = PEScanner()
    res = scanner.scan(str(empty_file))

    assert res["status"] == "ERROR"
    assert "empty" in res["error_message"].lower()


def test_scan_non_existent_file():
    scanner = PEScanner()
    res = scanner.scan("non_existent_file.exe")
    assert res["status"] == "ERROR"
    assert "does not exist" in res["error_message"].lower()


def test_pe_scanner_pipeline_integration(tmp_path: Path):
    """
    Tests full pipeline: PE Scanner -> CryptoClassifier -> RiskEngine -> Graph -> PQC Readiness -> Migration Engine.
    """
    _, der_cert = generate_rsa_certificate(key_size=2048)
    pe_file = tmp_path / "production_service.exe"
    pe_file.write_bytes(generate_signed_pe_file([der_cert], is_64bit=True))

    scanner = PEScanner()
    raw_res = scanner.scan(str(pe_file))
    assert raw_res["status"] == "SUCCESS"

    # Graph
    graph = DependencyGraph()
    graph.build_from_scan_result(raw_res, artifact_id="production_service.exe")
    assert graph.graph.number_of_nodes() >= 2  # Artifact + Cert

    # PQC Readiness
    pqc_engine = PQCReadinessEngine()
    pqc_res = pqc_engine.evaluate_readiness(raw_res, graph_engine=graph)
    assert pqc_res["readiness"]["state"] == ReadinessState.NOT_READY
    assert len(pqc_res["candidate_algorithms"]) >= 1

    # Migration Prioritization
    mig_engine = MigrationPrioritizationEngine()
    mig_plan = mig_engine.prioritize_all(raw_res["certificates"], graph_engine=graph)
    assert mig_plan["summary"]["total_targets"] == 1
    assert mig_plan["targets"][0]["priority_code"] in ("P1", "P2")


def test_cli_pe_scan_human_readable(tmp_path: Path):
    _, der_cert = generate_rsa_certificate(key_size=2048)
    pe_file = tmp_path / "payment_driver.sys"
    pe_file.write_bytes(generate_signed_pe_file([der_cert], is_64bit=True))

    res = runner.invoke(app, ["scan", str(pe_file)])
    assert res.exit_code == 0
    assert "SIGNCHAIN DISCOVERY SCAN" in res.stdout
    assert "payment_driver.sys" in res.stdout
    assert "RSA-2048" in res.stdout
    assert "VULNERABLE" in res.stdout


def test_cli_pe_scan_json_output(tmp_path: Path):
    pe_file = tmp_path / "test_unsigned.exe"
    pe_file.write_bytes(generate_unsigned_pe_file(is_64bit=True))

    res = runner.invoke(app, ["scan", str(pe_file), "--json"])
    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["status"] == "SUCCESS"
    assert parsed["certificates"][0]["authenticode_status"] == "UNSIGNED"
