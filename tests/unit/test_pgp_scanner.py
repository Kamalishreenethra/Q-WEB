"""
Unit tests for PGPScanner, OpenPGP key and signature discovery, and pipeline integration.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.scanners.pgp_scanner import PGPScanner
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine
from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType
from signchain.pqc.readiness_engine import PQCReadinessEngine, ReadinessState
from signchain.migration.migration_engine import MigrationPrioritizationEngine
from signchain.cli.main import app
from tests.fixtures.pgp import (
    generate_pgp_rsa_public_key,
    generate_pgp_ecdsa_public_key,
    generate_pgp_detached_signature,
    generate_pgp_signed_message,
)

runner = CliRunner()


def test_can_handle_pgp_files(tmp_path: Path):
    scanner = PGPScanner()

    # Valid extensions
    for ext in [".asc", ".gpg", ".pgp", ".sig"]:
        f = tmp_path / f"test{ext}"
        f.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----\n")
        assert scanner.can_handle(str(f)) is True

    # Non-PGP file
    txt_file = tmp_path / "plain.txt"
    txt_file.write_text("Simple text file.")
    assert scanner.can_handle(str(txt_file)) is False

    # Missing file
    assert scanner.can_handle(str(tmp_path / "missing.asc")) is False


def test_scan_pgp_rsa_public_key(tmp_path: Path):
    armored_key, _ = generate_pgp_rsa_public_key(key_size=2048, user_id="Alice Security <alice@example.com>")
    key_file = tmp_path / "alice_pubkey.asc"
    key_file.write_text(armored_key, encoding="utf-8")

    scanner = PGPScanner()
    res = scanner.scan(str(key_file))

    assert res["status"] == "SUCCESS"
    assert res["object_type"] == "PUBLIC_KEY"
    assert res["key_count"] == 1
    assert len(res["keys"]) == 1

    k = res["keys"][0]
    assert k["public_key_algorithm"] == "RSA"
    assert k["canonical_algorithm"] == "RSA-2048"
    assert k["key_size"] == 2048
    assert k["quantum_status"] == "VULNERABLE"
    assert k["risk_score"] >= 60.0
    assert "Alice Security" in k["user_ids"][0]
    assert len(k["fingerprint"]) == 40
    assert len(k["key_id"]) == 16


def test_scan_pgp_ecdsa_public_key(tmp_path: Path):
    armored_key, _ = generate_pgp_ecdsa_public_key(curve_name="NIST P-256", user_id="Bob ECC <bob@example.com>")
    key_file = tmp_path / "bob_ecc.asc"
    key_file.write_text(armored_key, encoding="utf-8")

    scanner = PGPScanner()
    res = scanner.scan(str(key_file))

    assert res["status"] == "SUCCESS"
    assert res["key_count"] == 1
    k = res["keys"][0]
    assert k["public_key_algorithm"] == "ECDSA"
    assert k["curve"] == "NIST P-256"
    assert k["quantum_status"] == "VULNERABLE"


def test_scan_pgp_detached_signature(tmp_path: Path):
    armored_sig, _ = generate_pgp_detached_signature(issuer_key_id_hex="A50FA65CB89290FB", pk_alg_id=1, hash_alg_id=8)
    sig_file = tmp_path / "release.tar.gz.sig"
    sig_file.write_text(armored_sig, encoding="utf-8")

    scanner = PGPScanner()
    res = scanner.scan(str(sig_file))

    assert res["status"] == "SUCCESS"
    assert res["object_type"] == "DETACHED_SIGNATURE"
    assert res["signature_count"] == 1

    sig = res["signatures"][0]
    assert sig["signature_type"] == "BINARY_DOCUMENT"
    assert sig["hash_algorithm"] == "SHA-256"
    assert sig["public_key_algorithm"] == "RSA"
    assert sig["issuer_key_id"] == "A50FA65CB89290FB"
    assert sig["signature_verification"] == "VERIFICATION_NOT_PERFORMED"
    assert sig["quantum_status"] == "VULNERABLE"


def test_scan_pgp_signed_message(tmp_path: Path):
    signed_msg = generate_pgp_signed_message("SignChain Core v1.0.0 Release", issuer_key_id_hex="1234567890ABCDEF")
    msg_file = tmp_path / "release_notes.asc"
    msg_file.write_text(signed_msg, encoding="utf-8")

    scanner = PGPScanner()
    res = scanner.scan(str(msg_file))

    assert res["status"] == "SUCCESS"
    assert res["object_type"] == "SIGNED_MESSAGE"
    assert res["signature_count"] == 1
    assert res["signatures"][0]["issuer_key_id"] == "1234567890ABCDEF"


def test_scan_binary_pgp_key(tmp_path: Path):
    _, raw_bytes = generate_pgp_rsa_public_key(key_size=2048, user_id="Binary User <bin@example.com>")
    bin_file = tmp_path / "keyring.gpg"
    bin_file.write_bytes(raw_bytes)

    scanner = PGPScanner()
    res = scanner.scan(str(bin_file))

    assert res["status"] == "SUCCESS"
    assert res["key_count"] == 1
    assert res["keys"][0]["canonical_algorithm"] == "RSA-2048"


def test_scan_invalid_pgp_data(tmp_path: Path):
    bad_file = tmp_path / "corrupted.asc"
    bad_file.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nINVALID_GARBAGE_BYTES\n=XXXX\n-----END PGP PUBLIC KEY BLOCK-----\n")

    scanner = PGPScanner()
    res = scanner.scan(str(bad_file))

    assert res["status"] == "ERROR"
    assert "error_message" in res


def test_scan_empty_pgp_file(tmp_path: Path):
    empty_file = tmp_path / "empty.asc"
    empty_file.write_text("")

    scanner = PGPScanner()
    res = scanner.scan(str(empty_file))
    assert res["status"] == "ERROR"
    assert "empty" in res["error_message"].lower()


def test_scan_oversized_pgp_file(tmp_path: Path):
    large_file = tmp_path / "large.asc"
    large_file.write_bytes(b"-----BEGIN PGP MESSAGE-----\n" + b"A" * 500)

    scanner = PGPScanner(max_file_size=200)
    res = scanner.scan(str(large_file))
    assert res["status"] == "ERROR"
    assert "exceeds maximum allowed size" in res["error_message"]


def test_scan_non_existent_pgp_file():
    scanner = PGPScanner()
    res = scanner.scan("non_existent_key.asc")
    assert res["status"] == "ERROR"
    assert "does not exist" in res["error_message"].lower()


def test_pgp_pipeline_integration(tmp_path: Path):
    """
    Tests complete intelligence pipeline:
    PGPScanner -> CryptoClassifier -> RiskEngine -> DependencyGraph (PGP_KEY/SIGNER/BELONGS_TO) -> PQC Readiness -> Migration Prioritization.
    """
    armored_key, _ = generate_pgp_rsa_public_key(key_size=2048, user_id="Release Team <release@signchain.org>")
    key_file = tmp_path / "release_key.asc"
    key_file.write_text(armored_key, encoding="utf-8")

    scanner = PGPScanner()
    raw_res = scanner.scan(str(key_file))
    assert raw_res["status"] == "SUCCESS"

    # Dependency Graph
    graph = DependencyGraph()
    graph.build_from_scan_result(raw_res, artifact_id="release_key.asc")
    stats = graph.get_graph_statistics()
    assert stats["total_nodes"] >= 2  # Artifact + PGP_KEY (+ SIGNER)

    # Check for SIGNER and BELONGS_TO edge
    has_signer = any(data.get("type") == NodeType.SIGNER for _, data in graph.graph.nodes(data=True))
    assert has_signer is True

    # PQC Readiness Engine
    pqc_engine = PQCReadinessEngine()
    pqc_res = pqc_engine.evaluate_readiness(raw_res, graph_engine=graph)
    assert pqc_res["readiness"]["state"] == ReadinessState.NOT_READY
    assert len(pqc_res["candidate_algorithms"]) >= 1

    # Migration Prioritization Engine
    mig_engine = MigrationPrioritizationEngine()
    mig_plan = mig_engine.prioritize_all(raw_res["certificates"], graph_engine=graph)
    assert mig_plan["summary"]["total_targets"] == 1
    assert mig_plan["targets"][0]["priority_code"] in ("P1", "P2")


def test_cli_pgp_scan_human_readable(tmp_path: Path):
    armored_sig, _ = generate_pgp_detached_signature(issuer_key_id_hex="F0E1D2C3B4A59687")
    sig_file = tmp_path / "package_v1.tar.gz.sig"
    sig_file.write_text(armored_sig, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(sig_file)])
    assert res.exit_code == 0
    assert "SIGNCHAIN DISCOVERY SCAN" in res.stdout
    assert "package_v1.tar.gz.sig" in res.stdout
    assert "OpenPGP" in res.stdout
    assert "VULNERABLE" in res.stdout


def test_cli_pgp_scan_json_output(tmp_path: Path):
    armored_key, _ = generate_pgp_rsa_public_key(key_size=2048, user_id="Deploy Key <deploy@corp.net>")
    key_file = tmp_path / "deploy.asc"
    key_file.write_text(armored_key, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(key_file), "--json"])
    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["status"] == "SUCCESS"
    assert len(parsed["certificates"]) == 1
    assert parsed["certificates"][0]["canonical_algorithm"] == "RSA-2048"
