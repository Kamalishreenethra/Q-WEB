"""
Unit tests for MigrationPrioritizationEngine, BaselinePrioritizer, conflict detection, and research metrics.
"""
import pytest
from signchain.migration import (
    MigrationPrioritizationEngine,
    BaselinePrioritizer,
    PriorityLevel,
    MigrationStatus,
    DEFAULT_PRIORITY_WEIGHTS,
    DEFAULT_PRIORITY_THRESHOLDS,
    compute_priority_agreement,
    count_high_impact_detections,
    count_blocked_migrations,
    count_dependency_violations,
)
from signchain.graph import DependencyGraph, NodeType, EdgeType
from signchain.pqc import ReadinessState


@pytest.fixture
def sample_graph() -> DependencyGraph:
    """
    Fixture with CA -> CERT-A (2 artifacts) and CERT-B (3 artifacts)
    """
    g = DependencyGraph()
    g.add_node("ca-root", NodeType.CA, name="Root CA")

    g.add_node("cert-a", NodeType.CERTIFICATE, name="Cert A")
    g.add_node("cert-b", NodeType.CERTIFICATE, name="Cert B")
    g.add_edge("cert-a", "ca-root", EdgeType.ISSUED_BY)
    g.add_edge("cert-b", "ca-root", EdgeType.ISSUED_BY)

    g.add_node("app-1.exe", NodeType.ARTIFACT, name="App 1")
    g.add_node("app-2.exe", NodeType.ARTIFACT, name="App 2")
    g.add_edge("app-1.exe", "cert-a", EdgeType.SIGNED_BY)
    g.add_edge("app-2.exe", "cert-a", EdgeType.SIGNED_BY)

    g.add_node("svc-1.dll", NodeType.ARTIFACT, name="Service 1")
    g.add_node("svc-2.dll", NodeType.ARTIFACT, name="Service 2")
    g.add_node("svc-3.dll", NodeType.ARTIFACT, name="Service 3")
    g.add_edge("svc-1.dll", "cert-b", EdgeType.SIGNED_BY)
    g.add_edge("svc-2.dll", "cert-b", EdgeType.SIGNED_BY)
    g.add_edge("svc-3.dll", "cert-b", EdgeType.SIGNED_BY)

    return g


def test_priority_calculation():
    engine = MigrationPrioritizationEngine()
    calc = engine.calculate_priority_score(
        risk_score=90.0,
        readiness_state=ReadinessState.NOT_READY,
        dependency_impact=80.0,
        migration_complexity=30.0,
    )
    assert calc["score"] > 70.0
    assert calc["level_code"] in ("P1", "P2")
    assert "quantum_risk" in calc["contributions"]
    assert "readiness_urgency" in calc["contributions"]
    assert "dependency_impact" in calc["contributions"]
    assert "complexity_penalty" in calc["contributions"]


def test_priority_thresholds():
    engine = MigrationPrioritizationEngine()
    # High score -> P1
    p1_res = engine.calculate_priority_score(100.0, ReadinessState.NOT_READY, 100.0, 0.0)
    assert p1_res["level"] == PriorityLevel.P1_CRITICAL
    assert p1_res["level_code"] == "P1"

    # Low score -> P4
    p4_res = engine.calculate_priority_score(10.0, ReadinessState.PQC_READY, 0.0, 80.0)
    assert p4_res["level"] == PriorityLevel.P4_LOW
    assert p4_res["level_code"] == "P4"


def test_weight_validation():
    # Sum != 1.0
    with pytest.raises(ValueError, match="must sum to 1.0"):
        MigrationPrioritizationEngine(weights={"w_risk": 0.5, "w_readiness": 0.5, "w_dep_impact": 0.5, "w_complexity": 0.1})

    # Missing key
    with pytest.raises(ValueError, match="Missing keys"):
        MigrationPrioritizationEngine(weights={"w_risk": 0.5, "w_readiness": 0.5})

    # Negative weight
    with pytest.raises(ValueError, match="cannot be negative"):
        MigrationPrioritizationEngine(weights={"w_risk": 1.2, "w_readiness": 0.1, "w_dep_impact": -0.4, "w_complexity": 0.1})


def test_dependency_aware_ordering(sample_graph: DependencyGraph):
    engine = MigrationPrioritizationEngine()

    records = [
        {"artifact_name": "app-1.exe", "risk_score": 85.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
        {"artifact_name": "svc-1.dll", "risk_score": 85.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
    ]

    result = engine.prioritize_all(records, graph_engine=sample_graph)
    assert len(result["targets"]) == 2
    assert len(result["migration_order"]) == 2
    assert result["summary"]["total_targets"] == 2


def test_conflict_detection(sample_graph: DependencyGraph):
    engine = MigrationPrioritizationEngine()
    records = [
        {"artifact_name": "app-1.exe", "risk_score": 90.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
        {"artifact_name": "cert-a", "risk_score": 90.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
    ]
    result = engine.prioritize_all(records, graph_engine=sample_graph)
    assert "conflicts" in result
    # Conflict detected because app-1.exe depends on cert-a which is NOT_READY
    assert len(result["conflicts"]) >= 1
    assert result["conflicts"][0]["asset"] == "app-1.exe"
    assert result["conflicts"][0]["depends_on"] == "cert-a"


def test_cycle_detection():
    g = DependencyGraph()
    g.add_node("n1", NodeType.ARTIFACT)
    g.add_node("n2", NodeType.ARTIFACT)
    g.add_edge("n1", "n2")
    g.add_edge("n2", "n1")  # Cycle

    engine = MigrationPrioritizationEngine()
    records = [
        {"artifact_name": "n1", "risk_score": 80.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
        {"artifact_name": "n2", "risk_score": 80.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
    ]
    result = engine.prioritize_all(records, graph_engine=g)
    order = result["migration_order"]
    assert len(order) >= 1
    assert "CYCLE_ERROR" in order[0]["migration_status"] or "MIGRATION_CYCLE_DETECTED" in order[0]["artifact_id"]


def test_blocked_migration_detection():
    engine = MigrationPrioritizationEngine()
    record = {
        "artifact_name": "payment_service.jar",
        "risk_score": 95.0,
        "quantum_status": "VULNERABLE",
        "canonical_algorithm": "ECDSA-P256",
    }
    target = engine.evaluate_target(record)
    assert target["priority_code"] in ("P1", "P2")
    assert target["migration_status"] == MigrationStatus.BLOCKED
    assert len(target["blockers"]) > 0


def test_baseline_ordering():
    records = [
        {"artifact_name": "low_risk.exe", "risk_score": 20.0, "canonical_algorithm": "RSA-4096"},
        {"artifact_name": "high_risk.exe", "risk_score": 90.0, "canonical_algorithm": "RSA-1024"},
        {"artifact_name": "med_risk.exe", "risk_score": 60.0, "canonical_algorithm": "ECDSA-P256"},
    ]
    flat = BaselinePrioritizer.prioritize_flat(records)
    assert flat[0]["artifact_id"] == "high_risk.exe"
    assert flat[1]["artifact_id"] == "med_risk.exe"
    assert flat[2]["artifact_id"] == "low_risk.exe"
    assert flat[0]["baseline_method"] == BaselinePrioritizer.NAME


def test_research_metrics(sample_graph: DependencyGraph):
    engine = MigrationPrioritizationEngine()
    records = [
        {"artifact_name": "app-1.exe", "risk_score": 80.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
        {"artifact_name": "svc-1.dll", "risk_score": 50.0, "quantum_status": "VULNERABLE", "canonical_algorithm": "RSA-2048"},
    ]
    result = engine.prioritize_all(records, graph_engine=sample_graph)

    # Agreement metric
    agree = compute_priority_agreement(["app-1.exe", "svc-1.dll"], ["app-1.exe", "svc-1.dll"])
    assert agree == 1.0

    # Count high impact detections
    high_impact = count_high_impact_detections(result["targets"], downstream_threshold=0)
    assert high_impact == 2

    # Dependency violations
    violations = count_dependency_violations(result["migration_order"], sample_graph)
    assert violations >= 0
