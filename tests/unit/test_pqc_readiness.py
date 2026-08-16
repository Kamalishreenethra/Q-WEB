"""
Unit tests for PQCReadinessEngine, knowledge base, evidence classification, and CLI.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.pqc import (
    PQCReadinessEngine,
    PQCKnowledgeBase,
    ReadinessState,
    MigrationPhase,
    CompatibilityStatus,
    EvidenceLevel,
    READINESS_DISCLAIMER,
)
from signchain.graph import DependencyGraph, NodeType, EdgeType
from signchain.cli.main import app

runner = CliRunner()


def test_rsa_not_ready():
    engine = PQCReadinessEngine()
    record = {
        "artifact_name": "app.exe",
        "format": "X.509 (PEM)",
        "canonical_algorithm": "RSA-2048",
        "quantum_status": "VULNERABLE",
        "algorithm_family": "CLASSICAL_FACTORIZATION",
    }
    res = engine.evaluate_readiness(record)

    assert res["readiness"]["state"] == ReadinessState.NOT_READY
    assert res["readiness"]["migration_phase"] == MigrationPhase.PHASE_1_ASSESSMENT
    assert len(res["candidate_algorithms"]) >= 1
    assert res["candidate_algorithms"][0]["name"] == "ML-DSA-65"
    assert len(res["blockers"]) > 0
    assert READINESS_DISCLAIMER in res["disclaimer"]


def test_ecdsa_not_ready():
    engine = PQCReadinessEngine()
    record = {
        "artifact_name": "service.jar",
        "canonical_algorithm": "ECDSA-P256",
        "quantum_status": "VULNERABLE",
        "algorithm_family": "CLASSICAL_ECC",
    }
    res = engine.evaluate_readiness(record)

    assert res["readiness"]["state"] == ReadinessState.NOT_READY
    assert res["readiness"]["migration_phase"] == MigrationPhase.PHASE_1_ASSESSMENT


def test_ed25519_not_ready():
    engine = PQCReadinessEngine()
    record = {
        "artifact_name": "container.img",
        "canonical_algorithm": "Ed25519",
        "quantum_status": "VULNERABLE",
    }
    res = engine.evaluate_readiness(record)

    assert res["readiness"]["state"] == ReadinessState.NOT_READY


def test_pqc_ready_ml_dsa():
    engine = PQCReadinessEngine()
    record = {
        "artifact_name": "pqc_signed.bin",
        "canonical_algorithm": "ML-DSA-65",
        "quantum_status": "QUANTUM_RESISTANT",
    }
    res = engine.evaluate_readiness(record)

    assert res["readiness"]["state"] == ReadinessState.PQC_READY
    assert res["readiness"]["migration_phase"] == MigrationPhase.PHASE_4_VERIFICATION
    assert len(res["blockers"]) == 0


def test_hybrid_ready():
    engine = PQCReadinessEngine()
    record = {
        "artifact_name": "hybrid_cert.pem",
        "canonical_algorithm": "RSA+ML-DSA",
        "quantum_status": "HYBRID_READY",
    }
    res = engine.evaluate_readiness(record)

    assert res["readiness"]["state"] == ReadinessState.HYBRID_READY
    assert res["readiness"]["migration_phase"] == MigrationPhase.PHASE_3_HYBRID_OR_PQC_DEPLOYMENT


def test_unknown_algorithm_and_missing_metadata():
    engine = PQCReadinessEngine()

    res_empty = engine.evaluate_readiness({})
    assert res_empty["readiness"]["state"] == ReadinessState.UNKNOWN
    assert res_empty["readiness"]["migration_phase"] == MigrationPhase.PHASE_0_DISCOVERY

    res_unknown = engine.evaluate_readiness({"quantum_status": "UNKNOWN"})
    assert res_unknown["readiness"]["state"] == ReadinessState.UNKNOWN


def test_candidate_pqc_identification():
    kb = PQCKnowledgeBase()

    cands_rsa = kb.get_recommended_candidates("RSA-2048")
    assert any(c["name"] == "ML-DSA-65" for c in cands_rsa)

    cands_high_sec = kb.get_recommended_candidates("RSA-4096")
    assert any(c["name"] == "ML-DSA-87" for c in cands_high_sec)


def test_evidence_levels():
    engine = PQCReadinessEngine()
    record = {"canonical_algorithm": "ECDSA-P256", "quantum_status": "VULNERABLE"}
    res = engine.evaluate_readiness(record)

    levels = [e["level"] for e in res["evidence"]]
    assert EvidenceLevel.OBSERVED in levels
    assert EvidenceLevel.INFERRED in levels
    assert EvidenceLevel.UNKNOWN in levels


def test_dependency_graph_impact_integration():
    fp = "1234567812345678123456781234567812345678123456781234567812345678"
    cert_id = f"cert:{fp[:16]}"

    # Build graph with CA -> CERT -> 3 Artifacts
    g = DependencyGraph()
    g.add_node("ca-1", NodeType.CA, name="Root CA")
    g.add_node(cert_id, NodeType.CERTIFICATE, name="Leaf Cert")
    g.add_edge(cert_id, "ca-1", EdgeType.ISSUED_BY)

    for i in range(3):
        art_id = f"art-{i}"
        g.add_node(art_id, NodeType.ARTIFACT, name=f"Artifact {i}")
        g.add_edge(art_id, cert_id, EdgeType.SIGNED_BY)

    engine = PQCReadinessEngine()
    record = {
        "artifact_name": "root_cert.pem",
        "sha256_fingerprint": fp,
        "canonical_algorithm": "RSA-2048",
        "quantum_status": "VULNERABLE",
    }
    res = engine.evaluate_readiness(record, graph_engine=g)

    assert res["dependency_impact"]["downstream_artifacts"] == 3
    assert res["dependency_impact"]["impact_level"] == "MEDIUM"


def test_cli_pqc_command(tmp_path: Path):
    scan_json = tmp_path / "scan_result.json"
    scan_json.write_text(json.dumps({
        "status": "SUCCESS",
        "certificates": [{
            "artifact_name": "payment_app.exe",
            "format": "X.509 (PEM)",
            "canonical_algorithm": "ECDSA-P256",
            "quantum_status": "VULNERABLE",
            "sha256_fingerprint": "abc123def4567890",
        }]
    }), encoding="utf-8")

    res = runner.invoke(app, ["pqc", str(scan_json)])
    assert res.exit_code == 0
    assert "SIGNCHAIN PQC READINESS ASSESSMENT" in res.stdout
    assert "NOT_READY" in res.stdout
    assert "ML-DSA-65" in res.stdout

    json_res = runner.invoke(app, ["pqc", str(scan_json), "--json"])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.stdout)
    assert parsed["readiness"]["state"] == "NOT_READY"
    assert parsed["current_cryptography"]["algorithm"] == "ECDSA-P256"
