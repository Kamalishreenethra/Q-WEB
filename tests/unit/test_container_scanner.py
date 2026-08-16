"""
Unit tests for ContainerScanner, OCI manifest parsing, Cosign signatures, Notary detection, and pipeline integration.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.scanners.container_scanner import ContainerScanner
from signchain.classifiers.crypto_classifier import CryptoClassifier
from signchain.risk.risk_engine import QuantumRiskEngine
from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType
from signchain.pqc.readiness_engine import PQCReadinessEngine, ReadinessState
from signchain.migration.migration_engine import MigrationPrioritizationEngine
from signchain.cli.main import app
from tests.fixtures.container import (
    generate_unsigned_oci_manifest,
    generate_cosign_signed_oci_manifest,
    generate_notary_signed_manifest,
    generate_multiarch_image_index,
)

runner = CliRunner()


def test_can_handle_container_files(tmp_path: Path):
    scanner = ContainerScanner()

    # Valid extensions
    for ext in [".oci.json", ".docker.json", ".manifest.json", ".container.json"]:
        f = tmp_path / f"test{ext}"
        f.write_text("{}", encoding="utf-8")
        assert scanner.can_handle(str(f)) is True

    # JSON with OCI manifest marker
    oci_file = tmp_path / "custom.json"
    oci_file.write_text(json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {},
        "layers": [],
    }), encoding="utf-8")
    assert scanner.can_handle(str(oci_file)) is True

    # Plain text file
    txt_file = tmp_path / "plain.txt"
    txt_file.write_text("Simple text.", encoding="utf-8")
    assert scanner.can_handle(str(txt_file)) is False


def test_scan_unsigned_oci_manifest(tmp_path: Path):
    manifest = generate_unsigned_oci_manifest(
        image_name="registry.example.com/payment/api:1.4.2",
        arch="amd64",
        os_name="linux",
    )
    manifest_file = tmp_path / "payment_api.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(manifest_file))

    assert res["status"] == "SUCCESS"
    assert res["ecosystem"] == "CONTAINER"
    assert res["artifact"]["repository"] == "payment/api"
    assert res["artifact"]["tag"] == "1.4.2"
    assert res["artifact"]["layer_count"] == 2
    assert res["signature"]["status"] == "UNSIGNED"
    assert res["signature"]["verification"] == "VERIFICATION_NOT_PERFORMED"
    assert res["quantum_status"] == "NOT_APPLICABLE"
    assert res["risk_score"] == 0.0
    assert res["risk_level"] == "LOW"


def test_scan_cosign_ecdsa_signed_manifest(tmp_path: Path):
    manifest = generate_cosign_signed_oci_manifest(
        key_type="ECDSA",
        image_name="registry.example.com/auth/service:2.0.0",
    )
    manifest_file = tmp_path / "auth_service.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(manifest_file))

    assert res["status"] == "SUCCESS"
    assert res["signature"]["status"] == "SIGNATURE_PRESENT"
    assert res["signature"]["ecosystem"] == "COSIGN"

    # Certificate & Quantum Status
    assert res["certificate"] is not None
    assert res["certificate"]["algorithm_family"] == "CLASSICAL_ECC"
    assert res["certificate"]["quantum_status"] == "VULNERABLE"
    assert res["risk_score"] >= 50.0
    assert res["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_scan_cosign_rsa_signed_manifest(tmp_path: Path):
    manifest = generate_cosign_signed_oci_manifest(
        key_type="RSA",
        image_name="registry.example.com/legacy/worker:1.0.0",
    )
    manifest_file = tmp_path / "legacy_worker.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(manifest_file))

    assert res["status"] == "SUCCESS"
    assert res["certificate"]["canonical_algorithm"] == "RSA-2048"
    assert res["certificate"]["quantum_status"] == "VULNERABLE"


def test_scan_notary_signed_manifest(tmp_path: Path):
    manifest = generate_notary_signed_manifest()
    manifest_file = tmp_path / "notary_sig.manifest.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(manifest_file))

    assert res["status"] == "SUCCESS"
    assert res["signature"]["ecosystem"] == "NOTARY_V2"
    assert res["signature"]["status"] == "SIGNATURE_PRESENT"


def test_scan_multiarch_image_index(tmp_path: Path):
    manifest = generate_multiarch_image_index()
    index_file = tmp_path / "index.oci.json"
    index_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(index_file))

    assert res["status"] == "SUCCESS"
    assert res["artifact"]["media_type"] == "application/vnd.oci.image.index.v1+json"


def test_scan_malformed_container_json(tmp_path: Path):
    bad_file = tmp_path / "broken.oci.json"
    bad_file.write_text("{ unclosed json", encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(bad_file))

    assert res["status"] == "ERROR"
    assert "Failed to parse JSON" in res["error_message"]


def test_scan_empty_container_file(tmp_path: Path):
    empty_file = tmp_path / "empty.oci.json"
    empty_file.write_text("", encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(empty_file))

    assert res["status"] == "ERROR"
    assert "empty" in res["error_message"].lower()


def test_scan_oversized_container_file(tmp_path: Path):
    large_file = tmp_path / "large.oci.json"
    large_file.write_text(json.dumps({"payload": "x" * 500}), encoding="utf-8")

    scanner = ContainerScanner(max_file_size=200)
    res = scanner.scan(str(large_file))

    assert res["status"] == "ERROR"
    assert "exceeds maximum allowed size" in res["error_message"]


def test_scan_non_existent_container_file():
    scanner = ContainerScanner()
    res = scanner.scan("non_existent_container.oci.json")
    assert res["status"] == "ERROR"
    assert "does not exist" in res["error_message"].lower()


def test_mutable_tag_vs_immutable_digest(tmp_path: Path):
    manifest = generate_unsigned_oci_manifest(image_name="myrepo/service:v1.2.3")
    manifest_file = tmp_path / "service.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    res = scanner.scan(str(manifest_file))

    art = res["artifact"]
    assert art["tag"] == "v1.2.3"
    assert art["tag_mutability"] == "MUTABLE"
    assert art["digest"].startswith("sha256:")
    assert art["digest_stability"] == "IMMUTABLE"


def test_container_pipeline_integration(tmp_path: Path):
    """
    Tests full pipeline integration:
    ContainerScanner -> CryptoClassifier -> RiskEngine -> DependencyGraph (CONTAINER, SIGNED_BY, CONTAINS) -> PQC Readiness -> Migration Prioritization.
    """
    manifest = generate_cosign_signed_oci_manifest(
        key_type="ECDSA",
        image_name="registry.corp.internal/production/database:5.7",
    )
    manifest_file = tmp_path / "database.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    raw_res = scanner.scan(str(manifest_file))
    assert raw_res["status"] == "SUCCESS"

    # Dependency Graph
    graph = DependencyGraph()
    graph.build_from_scan_result(raw_res, artifact_id="database.oci.json")
    stats = graph.get_graph_statistics()
    assert stats["total_nodes"] >= 3  # Container + Layer + Certificate

    # Verify node types in graph
    types = {data.get("type") for _, data in graph.graph.nodes(data=True)}
    assert NodeType.CONTAINER in types
    assert NodeType.CERTIFICATE in types

    # PQC Readiness Engine
    pqc_engine = PQCReadinessEngine()
    pqc_res = pqc_engine.evaluate_readiness(raw_res, graph_engine=graph)
    assert pqc_res["readiness"]["state"] == ReadinessState.NOT_READY

    # Migration Engine
    mig_engine = MigrationPrioritizationEngine()
    mig_plan = mig_engine.prioritize_all(raw_res["certificates"], graph_engine=graph)
    assert mig_plan["summary"]["total_targets"] == 1
    assert mig_plan["targets"][0]["priority_code"] in ("P1", "P2", "P3")


def test_cli_container_scan_human_readable(tmp_path: Path):
    manifest = generate_unsigned_oci_manifest(image_name="registry.io/app/frontend:v1")
    manifest_file = tmp_path / "frontend.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    res = runner.invoke(app, ["scan", str(manifest_file)])
    assert res.exit_code == 0
    assert "SIGNCHAIN DISCOVERY SCAN" in res.stdout
    assert "frontend.oci.json" in res.stdout


def test_cli_container_command_json(tmp_path: Path):
    manifest = generate_cosign_signed_oci_manifest(image_name="registry.io/app/backend:v1")
    manifest_file = tmp_path / "backend.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    res = runner.invoke(app, ["container", str(manifest_file), "--json"])
    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["status"] == "SUCCESS"
    assert parsed["ecosystem"] == "CONTAINER"
    assert parsed["signature"]["ecosystem"] == "COSIGN"
