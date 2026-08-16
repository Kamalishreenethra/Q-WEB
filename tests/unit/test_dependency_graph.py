"""
Unit tests for NetworkX DependencyGraph engine, graph queries, centrality, risk engine integration, and CLI commands.
"""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from signchain.graph import DependencyGraph, NodeType, EdgeType
from signchain.risk import QuantumRiskEngine
from signchain.cli.main import app

runner = CliRunner()


@pytest.fixture
def deterministic_test_graph() -> DependencyGraph:
    """
    Creates a deterministic test graph fixture matching Section 12 specification:
    CA-1
     ├── CERT-1
     │      ├── ART-1
     │      └── ART-2
     │
     └── CERT-2
            ├── ART-3
            ├── ART-4
            └── ART-5
    """
    g = DependencyGraph()
    # Add CA
    g.add_node("ca-001", NodeType.CA, name="Root CA 1")

    # Add Certificates
    g.add_node("cert-001", NodeType.CERTIFICATE, name="Signing Cert 1")
    g.add_node("cert-002", NodeType.CERTIFICATE, name="Signing Cert 2")
    g.add_edge("cert-001", "ca-001", EdgeType.ISSUED_BY)
    g.add_edge("cert-002", "ca-001", EdgeType.ISSUED_BY)

    # Add Artifacts under CERT-1
    g.add_node("art-001", NodeType.ARTIFACT, name="Artifact 1")
    g.add_node("art-002", NodeType.ARTIFACT, name="Artifact 2")
    g.add_edge("art-001", "cert-001", EdgeType.SIGNED_BY)
    g.add_edge("art-002", "cert-001", EdgeType.SIGNED_BY)

    # Add Artifacts under CERT-2
    g.add_node("art-003", NodeType.ARTIFACT, name="Artifact 3")
    g.add_node("art-004", NodeType.ARTIFACT, name="Artifact 4")
    g.add_node("art-005", NodeType.ARTIFACT, name="Artifact 5")
    g.add_edge("art-003", "cert-002", EdgeType.SIGNED_BY)
    g.add_edge("art-004", "cert-002", EdgeType.SIGNED_BY)
    g.add_edge("art-005", "cert-002", EdgeType.SIGNED_BY)

    return g


def test_node_and_edge_creation():
    g = DependencyGraph()
    g.add_node("n1", NodeType.ARTIFACT, name="Node 1", metadata={"key": "val"})
    g.add_node("n2", NodeType.CERTIFICATE, name="Node 2")
    g.add_edge("n1", "n2", EdgeType.SIGNED_BY)

    node1 = g.get_node("n1")
    assert node1["type"] == NodeType.ARTIFACT
    assert node1["name"] == "Node 1"
    assert node1["metadata"] == {"key": "val"}

    assert g.graph.has_edge("n1", "n2")


def test_duplicate_node_and_edge_handling():
    g = DependencyGraph()
    g.add_node("n1", NodeType.ARTIFACT, name="Original Name")
    g.add_node("n1", NodeType.ARTIFACT, name="Updated Name", metadata={"added": True})

    assert g.graph.number_of_nodes() == 1
    node = g.get_node("n1")
    assert node["name"] == "Updated Name"
    assert node["metadata"]["added"] is True

    g.add_edge("n1", "n2", EdgeType.SIGNED_BY)
    g.add_edge("n1", "n2", EdgeType.SIGNED_BY)
    assert g.graph.number_of_edges() == 1


def test_missing_node_handling():
    g = DependencyGraph()
    assert g.get_node("non_existent") is None
    assert g.get_neighbors("non_existent") == []
    assert g.find_artifacts_signed_by("non_existent") == []
    assert g.get_dependency_count("non_existent") == 0
    assert g.remove_node("non_existent") is False
    assert g.remove_edge("n1", "n2") is False


def test_deterministic_test_graph_traversal(deterministic_test_graph: DependencyGraph):
    g = deterministic_test_graph

    # CERT-1 -> 2 downstream artifacts (ART-1, ART-2)
    deps_cert1 = g.find_artifacts_signed_by("cert-001")
    assert deps_cert1 == ["art-001", "art-002"]
    assert g.get_dependency_count("cert-001") == 2

    # CERT-2 -> 3 downstream artifacts (ART-3, ART-4, ART-5)
    deps_cert2 = g.find_artifacts_signed_by("cert-002")
    assert deps_cert2 == ["art-003", "art-004", "art-005"]
    assert g.get_dependency_count("cert-002") == 3

    # CA-1 -> 5 downstream artifacts (all)
    deps_ca1 = g.find_artifacts_signed_by("ca-001")
    assert deps_ca1 == ["art-001", "art-002", "art-003", "art-004", "art-005"]
    assert g.get_dependency_count("ca-001") == 5


def test_find_certificates_for_artifact(deterministic_test_graph: DependencyGraph):
    g = deterministic_test_graph
    certs = g.find_certificates_for_artifact("art-001")
    assert certs == ["cert-001"]


def test_graph_statistics(deterministic_test_graph: DependencyGraph):
    g = deterministic_test_graph
    stats = g.get_graph_statistics()

    assert stats["total_nodes"] == 8  # 5 artifacts + 2 certs + 1 CA
    assert stats["total_edges"] == 7  # 5 signed_by + 2 issued_by
    assert stats["artifacts_count"] == 5
    assert stats["certificates_count"] == 2
    assert stats["cas_count"] == 1

    top = stats["top_signing_dependencies"]
    assert len(top) > 0
    # CA-1 has highest downstream artifacts count (5)
    assert top[0]["id"] == "ca-001"
    assert top[0]["downstream_artifacts_count"] == 5


def test_centrality_calculation(deterministic_test_graph: DependencyGraph):
    g = deterministic_test_graph
    cent = g.calculate_centrality()

    assert "degree_centrality" in cent
    assert "betweenness_centrality" in cent
    assert "ca-001" in cent["degree_centrality"]


def test_json_and_graphml_serialization(deterministic_test_graph: DependencyGraph):
    g = deterministic_test_graph

    json_str = g.export_json()
    parsed = json.loads(json_str)
    assert len(parsed["nodes"]) == 8
    assert len(parsed["edges"]) == 7
    assert "statistics" in parsed

    graphml_str = g.export_graphml()
    assert "<graphml" in graphml_str
    assert "art-001" in graphml_str


def test_risk_engine_dependency_impact_normalization():
    # 0 downstream dependencies -> 0.0
    assert QuantumRiskEngine.normalize_dependency_impact(0) == 0.0

    # 1 downstream dependency -> ~17.7
    score_1 = QuantumRiskEngine.normalize_dependency_impact(1)
    assert 15.0 < score_1 < 20.0

    # 25 downstream dependencies -> ~83.2
    score_25 = QuantumRiskEngine.normalize_dependency_impact(25)
    assert 80.0 < score_25 < 86.0

    # 50 downstream dependencies -> 100.0
    assert QuantumRiskEngine.normalize_dependency_impact(50) == 100.0

    # >50 downstream dependencies -> capped at 100.0
    assert QuantumRiskEngine.normalize_dependency_impact(100) == 100.0


def test_graph_benchmark_utility():
    g = DependencyGraph()
    bench = g.benchmark_graph_construction(node_count=20)

    assert bench["benchmark_nodes"] > 0
    assert "construction_time_sec" in bench
    assert "traversal_time_sec" in bench
    assert "centrality_time_sec" in bench


def test_cli_graph_command(deterministic_test_graph: DependencyGraph, tmp_path: Path):
    graph_file = tmp_path / "graph.json"
    graph_file.write_text(deterministic_test_graph.export_json(), encoding="utf-8")

    result = runner.invoke(app, ["graph", str(graph_file)])
    assert result.exit_code == 0
    assert "SIGNCHAIN DEPENDENCY GRAPH" in result.stdout
    assert "Total Nodes : 8" in result.stdout

    json_res = runner.invoke(app, ["graph", str(graph_file), "--json"])
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.stdout)
    assert parsed["statistics"]["total_nodes"] == 8
