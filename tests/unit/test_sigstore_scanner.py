"""
Unit tests for SigstoreScanner, Fulcio certificate identity extraction, Rekor evidence, and pipeline integration.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.scanners.sigstore_scanner import SigstoreScanner
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine
from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType
from signchain.pqc.readiness_engine import PQCReadinessEngine, ReadinessState
from signchain.migration.migration_engine import MigrationPrioritizationEngine
from signchain.cli.main import app
from tests.fixtures.sigstore import (
    generate_sigstore_v03_bundle,
    generate_sigstore_dsse_bundle,
)

runner = CliRunner()


def test_can_handle_sigstore_files(tmp_path: Path):
    scanner = SigstoreScanner()

    # Valid extensions
    for ext in [".sigstore.json", ".bundle", ".sigstore", ".dsse"]:
        f = tmp_path / f"test{ext}"
        f.write_text("{}", encoding="utf-8")
        assert scanner.can_handle(str(f)) is True

    # JSON with Sigstore mediaType marker
    json_bundle = tmp_path / "artifact.json"
    json_bundle.write_text(json.dumps({"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"}), encoding="utf-8")
    assert scanner.can_handle(str(json_bundle)) is True

    # Plain text file
    plain_txt = tmp_path / "readme.txt"
    plain_txt.write_text("Hello World", encoding="utf-8")
    assert scanner.can_handle(str(plain_txt)) is False


def test_scan_valid_sigstore_v03_bundle(tmp_path: Path):
    bundle_data = generate_sigstore_v03_bundle(
        key_type="ECDSA",
        san_email="ci-builder@signchain.org",
        artifact_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    )
    bundle_file = tmp_path / "release.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bundle_file))

    assert res["status"] == "SUCCESS"
    assert res["ecosystem"] == "SIGSTORE"
    assert "0.3" in res["media_type"]
    assert res["artifact"]["digest"]["algorithm"] == "SHA-256"
    assert "abcdef012345" in res["artifact"]["digest"]["value"]

    # Certificate & Identity
    assert res["certificate"] is not None
    assert res["certificate"]["algorithm_family"] == "CLASSICAL_ECC"
    assert res["certificate"]["public_key_algorithm"] == "ECDSA"
    assert res["certificate"]["quantum_status"] == "VULNERABLE"
    assert res["identity"]["value"] == "ci-builder@signchain.org"
    assert res["identity"]["type"] == "EMAIL"

    # Transparency Log
    tlog = res["transparency"]
    assert tlog["status"] == "PRESENT"
    assert tlog["entries_count"] == 1
    assert tlog["entries"][0]["log_index"] == "19482711"


def test_scan_sigstore_rsa_bundle(tmp_path: Path):
    bundle_data = generate_sigstore_v03_bundle(
        key_type="RSA",
        san_email="admin@enterprise.org",
    )
    bundle_file = tmp_path / "rsa_bundle.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bundle_file))

    assert res["status"] == "SUCCESS"
    assert res["certificate"]["canonical_algorithm"] == "RSA-2048"
    assert res["certificate"]["quantum_status"] == "VULNERABLE"


def test_scan_sigstore_dsse_in_toto_bundle(tmp_path: Path):
    bundle_data = generate_sigstore_dsse_bundle(
        subject_name="signchain-lib.tgz",
        subject_sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    )
    bundle_file = tmp_path / "provenance.dsse"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bundle_file))

    assert res["status"] == "SUCCESS"
    assert res["artifact"]["digest"]["algorithm"] == "SHA256"
    assert res["artifact"]["digest"]["value"] == "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
    assert res["signing"]["signature_status"] == "SIGNATURE_PRESENT"


def test_scan_sigstore_bundle_missing_certificate(tmp_path: Path):
    bundle_data = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {},
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": "AAAA"},
            "signature": "BBBB",
        },
    }
    bundle_file = tmp_path / "no_cert.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bundle_file))

    assert res["status"] == "SUCCESS"
    assert res["certificate"] is None
    assert len(res["certificates"]) == 0


def test_scan_sigstore_bundle_missing_transparency_proof(tmp_path: Path):
    bundle_data = generate_sigstore_v03_bundle(include_tlog=False)
    bundle_file = tmp_path / "no_tlog.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bundle_file))

    assert res["status"] == "SUCCESS"
    assert res["transparency"]["status"] == "MISSING"
    assert res["transparency"]["entries_count"] == 0


def test_scan_malformed_sigstore_json(tmp_path: Path):
    bad_file = tmp_path / "broken.sigstore.json"
    bad_file.write_text("{ unclosed json structure ...", encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bad_file))

    assert res["status"] == "ERROR"
    assert "Failed to parse JSON" in res["error_message"]


def test_scan_empty_sigstore_file(tmp_path: Path):
    empty_file = tmp_path / "empty.sigstore.json"
    empty_file.write_text("", encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(empty_file))

    assert res["status"] == "ERROR"
    assert "empty" in res["error_message"].lower()


def test_scan_oversized_sigstore_file(tmp_path: Path):
    large_file = tmp_path / "large.sigstore.json"
    large_file.write_text(json.dumps({"data": "x" * 500}), encoding="utf-8")

    scanner = SigstoreScanner(max_file_size=200)
    res = scanner.scan(str(large_file))

    assert res["status"] == "ERROR"
    assert "exceeds maximum allowed size" in res["error_message"]


def test_scan_non_existent_sigstore_file():
    scanner = SigstoreScanner()
    res = scanner.scan("missing_sigstore_file.sigstore.json")
    assert res["status"] == "ERROR"
    assert "does not exist" in res["error_message"].lower()


def test_sigstore_fulcio_identity_claims(tmp_path: Path):
    bundle_data = generate_sigstore_v03_bundle(
        san_uri="https://github.com/signchain/release/.github/workflows/deploy.yml@refs/heads/main",
        san_email=None,
    )
    bundle_file = tmp_path / "claims.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    res = scanner.scan(str(bundle_file))

    assert res["status"] == "SUCCESS"
    ident = res["identity"]
    assert ident["type"] == "URI"
    assert "github.com/signchain/release" in ident["value"]
    assert ident["issuer"] == "https://token.actions.githubusercontent.com"
    assert ident["claims"].get("github_repo") == "signchain/core"


def test_sigstore_pipeline_integration(tmp_path: Path):
    """
    Tests complete pipeline integration:
    SigstoreScanner -> CryptoClassifier -> RiskEngine -> DependencyGraph (SIGSTORE, TRANSPARENCY_ENTRY, SIGNER) -> PQC Readiness -> Migration Prioritization.
    """
    bundle_data = generate_sigstore_v03_bundle(san_email="bot@signchain.org")
    bundle_file = tmp_path / "app.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    scanner = SigstoreScanner()
    raw_res = scanner.scan(str(bundle_file))
    assert raw_res["status"] == "SUCCESS"

    # Dependency Graph
    graph = DependencyGraph()
    graph.build_from_scan_result(raw_res, artifact_id="app.sigstore.json")
    stats = graph.get_graph_statistics()
    assert stats["total_nodes"] >= 3  # Artifact + Certificate + Rekor Entry + Signer

    # Verify node types in graph
    types = {data.get("type") for _, data in graph.graph.nodes(data=True)}
    assert NodeType.SIGNER in types
    assert NodeType.TRANSPARENCY_ENTRY in types

    # PQC Readiness Engine
    pqc_engine = PQCReadinessEngine()
    pqc_res = pqc_engine.evaluate_readiness(raw_res, graph_engine=graph)
    assert pqc_res["readiness"]["state"] == ReadinessState.NOT_READY

    # Migration Engine
    mig_engine = MigrationPrioritizationEngine()
    mig_plan = mig_engine.prioritize_all(raw_res["certificates"], graph_engine=graph)
    assert mig_plan["summary"]["total_targets"] == 1
    assert mig_plan["targets"][0]["priority_code"] in ("P1", "P2")


def test_cli_sigstore_scan_human_readable(tmp_path: Path):
    bundle_data = generate_sigstore_v03_bundle(san_email="cli_test@signchain.org")
    bundle_file = tmp_path / "package.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    res = runner.invoke(app, ["scan", str(bundle_file)])
    assert res.exit_code == 0
    assert "SIGNCHAIN DISCOVERY SCAN" in res.stdout
    assert "package.sigstore.json" in res.stdout
    assert "VULNERABLE" in res.stdout


def test_cli_sigstore_command_json(tmp_path: Path):
    bundle_data = generate_sigstore_v03_bundle(san_email="json_test@signchain.org")
    bundle_file = tmp_path / "build.sigstore.json"
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    res = runner.invoke(app, ["sigstore", str(bundle_file), "--json"])
    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["status"] == "SUCCESS"
    assert parsed["ecosystem"] == "SIGSTORE"
    assert parsed["identity"]["value"] == "json_test@signchain.org"
