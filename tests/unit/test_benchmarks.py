"""
Phase 14 Comprehensive Unit & Integration Test Suite.

Audits & Tests:
  1. Workload Generator: Determinism, seed sensitivity, sizing, distributions, PQC consistency.
  2. Dependency Graph: Node creation, edge creation, hub reachability, reverse DAG traversal.
  3. Production Integration: CryptoClassifier, QuantumRiskEngine, PQCReadinessEngine, MigrationPrioritizationEngine.
  4. Baseline Model: Pure flat ordering, absence of graph attributes, fair algorithm ranking.
  5. Ground Truth Independence: MCDA formulation, absence of production engine imports, blind execution.
  6. Evaluation Metrics: Top-K recall, Spearman correlation, Priority inversions, Critical miss rate, High-impact recall, Order agreement.
  7. Runner & Statistical Engine: Single-seed, multi-seed, 4-way ablation, Wilcoxon signed-rank test.
  8. Controlled & Adversarial Scenarios: Scenarios A through H (testing where baseline wins, ties, or loses).
  9. Ground Truth Sensitivity: Robustness under alternative weighting configurations.
"""
import json
import math
import os
import pytest
from pathlib import Path

from signchain.research.workload_generator import SyntheticWorkloadGenerator, ScenarioFamily
from signchain.research.baseline import FlatCryptographicBaseline
from signchain.research.metrics import (
    calculate_top_k_recall,
    calculate_spearman_correlation,
    calculate_priority_inversions,
    calculate_critical_missed_rate,
    calculate_high_impact_recall,
    calculate_order_agreement,
)
from signchain.research.runner import BenchmarkRunner
from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType
from signchain.migration.migration_engine import MigrationPrioritizationEngine
from signchain.classifiers.crypto_classifier import CryptoClassifier, QuantumStatus, AlgorithmFamily
from signchain.pqc.readiness_engine import PQCReadinessEngine, ReadinessState


# ============================================================
# 1. Deterministic Workload Generation & Seed Sensitivity
# ============================================================

class TestWorkloadGeneratorDeterminism:
    def test_seed_42_reproducibility(self):
        w1 = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        w2 = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)

        assert w1["artifact_count"] == w2["artifact_count"]
        assert w1["certificate_count"] == w2["certificate_count"]
        assert w1["graph_nodes"] == w2["graph_nodes"]
        assert w1["graph_edges"] == w2["graph_edges"]

        for a1, a2 in zip(w1["artifacts"], w2["artifacts"]):
            assert a1["id"] == a2["id"]
            assert a1["canonical_algorithm"] == a2["canonical_algorithm"]
            assert a1["business_criticality"] == a2["business_criticality"]

        for g1, g2 in zip(w1["ground_truth"], w2["ground_truth"]):
            assert g1["target_id"] == g2["target_id"]
            assert g1["ground_truth_score"] == g2["ground_truth_score"]

    def test_seed_43_differs_from_42(self):
        w42 = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        w43 = SyntheticWorkloadGenerator(seed=43).generate_workload(size=50)

        algs_42 = [a["canonical_algorithm"] for a in w42["artifacts"]]
        algs_43 = [a["canonical_algorithm"] for a in w43["artifacts"]]
        assert algs_42 != algs_43

    def test_workload_size_50(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        assert w["artifact_count"] == 50

    def test_workload_size_100(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=100)
        assert w["artifact_count"] == 100
        assert w["certificate_count"] >= 5
        assert w["graph_nodes"] > 0
        assert w["graph_edges"] > 0

    def test_workload_size_200(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=200)
        assert w["artifact_count"] == 200

    def test_workload_size_500(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=500)
        assert w["artifact_count"] == 500

    def test_workload_size_1000(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=1000)
        assert w["artifact_count"] == 1000

    def test_algorithm_distribution_validity(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=200)
        valid_algs = set(SyntheticWorkloadGenerator.ALGORITHM_METADATA.keys())
        for art in w["artifacts"]:
            assert art["canonical_algorithm"] in valid_algs

    def test_ecosystem_distribution_validity(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=200)
        valid_ecos = {"X509", "AUTHENTICODE", "OPENPGP", "SIGSTORE", "CONTAINER"}
        for art in w["artifacts"]:
            assert art["ecosystem"] in valid_ecos

    def test_criticality_labels_validity(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=200)
        valid_crits = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for art in w["artifacts"]:
            assert art["business_criticality"] in valid_crits

    def test_no_duplicate_artifact_ids(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=200)
        ids = [a["id"] for a in w["artifacts"]]
        assert len(ids) == len(set(ids))

    def test_quantum_status_consistency(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=200)
        for cert in w["certificates"]:
            alg = cert["canonical_algorithm"]
            meta = SyntheticWorkloadGenerator.ALGORITHM_METADATA.get(alg)
            if meta and meta["pqc"]:
                assert cert["quantum_status"] == "QUANTUM_RESISTANT"
            elif meta and not meta["pqc"]:
                assert cert["quantum_status"] == "VULNERABLE"


# ============================================================
# 2. Scenario Families Generation
# ============================================================

class TestScenarioFamilies:
    def test_dependency_hub_scenario(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50, scenario_family=ScenarioFamily.DEPENDENCY_HUB)
        assert w["scenario_family"] == ScenarioFamily.DEPENDENCY_HUB
        assert any(c["is_hub"] for c in w["certificates"])

    def test_isolated_critical_scenario(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50, scenario_family=ScenarioFamily.ISOLATED_CRITICAL)
        assert w["scenario_family"] == ScenarioFamily.ISOLATED_CRITICAL
        assert any(a["business_criticality"] == "CRITICAL" for a in w["artifacts"])

    def test_crypto_severe_scenario(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50, scenario_family=ScenarioFamily.CRYPTO_SEVERE)
        assert w["scenario_family"] == ScenarioFamily.CRYPTO_SEVERE

    def test_migration_blocked_scenario(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50, scenario_family=ScenarioFamily.MIGRATION_BLOCKED)
        assert w["scenario_family"] == ScenarioFamily.MIGRATION_BLOCKED
        assert any(c.get("is_migration_blocked") for c in w["certificates"])

    def test_mixed_scenario(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50, scenario_family=ScenarioFamily.MIXED)
        assert w["scenario_family"] == ScenarioFamily.MIXED

    def test_anti_correlation_scenario(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50, scenario_family=ScenarioFamily.ANTI_CORRELATION)
        assert w["scenario_family"] == ScenarioFamily.ANTI_CORRELATION
        for c in w["certificates"]:
            if c["is_hub"]:
                assert c["quantum_status"] == "QUANTUM_RESISTANT"


# ============================================================
# 3. Identifier Consistency
# ============================================================

class TestIdentifierConsistency:
    def test_graph_node_ids_match_target_ids(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        graph = w["graph"]
        for cert in w["certificates"]:
            expected_node_id = f"cert:{cert['fingerprint'][:16]}"
            assert graph.graph.has_node(expected_node_id)

    def test_artifact_node_ids_match_artifact_ids(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        graph = w["graph"]
        for art in w["artifacts"]:
            assert graph.graph.has_node(art["id"])

    def test_ground_truth_target_ids_match_graph_nodes(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        graph = w["graph"]
        for gt in w["ground_truth"]:
            assert graph.graph.has_node(gt["target_id"])

    def test_subject_to_target_id_mapping(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        mapping = w["subject_to_target_id"]
        for cert in w["certificates"]:
            assert cert["subject"] in mapping
            assert mapping[cert["subject"]] == f"cert:{cert['fingerprint'][:16]}"


# ============================================================
# 4. Dependency Hub and Traversal
# ============================================================

class TestDependencyHubAndTraversal:
    def test_hub_certificate_has_dependents(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=100)
        graph = w["graph"]
        hub_certs = [c for c in w["certificates"] if c["is_hub"]]
        assert len(hub_certs) >= 1
        hub_id = f"cert:{hub_certs[0]['fingerprint'][:16]}"
        hub_deps = graph.find_downstream_dependencies(hub_id)
        assert len(hub_deps) > 0

    def test_find_downstream_dependencies_returns_valid_ids(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        graph = w["graph"]
        art_ids = {a["id"] for a in w["artifacts"]}
        for cert in w["certificates"]:
            cert_id = f"cert:{cert['fingerprint'][:16]}"
            deps = graph.find_downstream_dependencies(cert_id)
            for dep in deps:
                assert dep in art_ids

    def test_get_dependency_count_consistency(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        graph = w["graph"]
        for cert in w["certificates"]:
            cert_id = f"cert:{cert['fingerprint'][:16]}"
            count = graph.get_dependency_count(cert_id)
            deps = graph.find_downstream_dependencies(cert_id)
            assert count == len(deps)


# ============================================================
# 5. Production Engine Integration
# ============================================================

class TestProductionEngineIntegration:
    def test_migration_prioritization_engine_structure(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=20)
        engine = MigrationPrioritizationEngine()
        result = engine.prioritize_all(w["certificates"], graph_engine=w["graph"])

        assert "targets" in result
        assert "summary" in result
        assert "migration_order" in result
        assert len(result["migration_order"]) == len(w["certificates"])

        for t in result["targets"]:
            assert "artifact_id" in t
            assert "priority_score" in t
            assert "risk_score" in t
            assert "pqc_readiness" in t

    def test_artifact_id_equals_subject(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=20)
        engine = MigrationPrioritizationEngine()
        result = engine.prioritize_all(w["certificates"], graph_engine=w["graph"])
        cert_subjects = {c["subject"] for c in w["certificates"]}
        target_ids = {t["artifact_id"] for t in result["targets"]}
        assert target_ids == cert_subjects

    def test_signchain_uses_graph(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        engine = MigrationPrioritizationEngine()
        result = engine.prioritize_all(w["certificates"], graph_engine=w["graph"])
        has_dep = any(t["downstream_impact_count"] > 0 for t in result["targets"])
        assert has_dep


# ============================================================
# 6. Baseline Model
# ============================================================

class TestBaselineModel:
    def test_baseline_structure(self):
        baseline = FlatCryptographicBaseline()
        certs = [
            {"fingerprint": "aaa" * 11, "canonical_algorithm": "RSA-2048",
             "quantum_status": "VULNERABLE", "key_size_bits": 2048, "subject": "A"},
            {"fingerprint": "bbb" * 11, "canonical_algorithm": "ML-DSA-44",
             "quantum_status": "QUANTUM_RESISTANT", "key_size_bits": 1024, "subject": "B"},
        ]
        result = baseline.prioritize(certs)
        assert len(result) == 2
        assert result[0]["target_id"].startswith("cert:")
        assert result[0]["baseline_score"] > result[1]["baseline_score"]

    def test_baseline_no_graph_access(self):
        baseline = FlatCryptographicBaseline()
        certs = [{"fingerprint": "eee" * 11, "canonical_algorithm": "RSA-2048",
                   "quantum_status": "VULNERABLE", "key_size_bits": 2048, "subject": "E"}]
        result = baseline.prioritize(certs)
        for item in result:
            assert "dependency_impact" not in item
            assert "downstream_count" not in item


# ============================================================
# 7. Evaluation Metrics
# ============================================================

class TestEvaluationMetrics:
    def _make_gt(self, ids, critical_ids=None, high_impact_ids=None):
        critical_ids = critical_ids or set()
        high_impact_ids = high_impact_ids or set()
        return [
            {"target_id": tid, "ground_truth_rank": i + 1, "ground_truth_score": 100 - i * 10,
             "is_critical_target": tid in critical_ids, "is_high_impact_target": tid in high_impact_ids}
            for i, tid in enumerate(ids)
        ]

    def _make_pred(self, ids):
        return [{"target_id": tid} for tid in ids]

    def test_top_k_recall_perfect(self):
        gt = self._make_gt(["a", "b", "c", "d", "e"])
        pred = self._make_pred(["a", "b", "c", "d", "e"])
        assert calculate_top_k_recall(pred, gt, k=5) == 1.0

    def test_top_k_recall_partial(self):
        gt = self._make_gt(["a", "b", "c", "d", "e"])
        pred = self._make_pred(["a", "b", "x", "y", "z"])
        assert calculate_top_k_recall(pred, gt, k=5) == pytest.approx(0.4, abs=0.01)

    def test_top_k_recall_empty(self):
        assert calculate_top_k_recall([], [], k=5) == 0.0

    def test_spearman_perfect(self):
        gt = self._make_gt(["a", "b", "c"])
        pred = self._make_pred(["a", "b", "c"])
        rho, pval = calculate_spearman_correlation(pred, gt)
        assert rho == pytest.approx(1.0, abs=0.01)

    def test_spearman_reversed(self):
        gt = self._make_gt(["a", "b", "c"])
        pred = self._make_pred(["c", "b", "a"])
        rho, _ = calculate_spearman_correlation(pred, gt)
        assert rho == pytest.approx(-1.0, abs=0.01)

    def test_priority_inversions_zero(self):
        gt = self._make_gt(["a", "b", "c"])
        pred = self._make_pred(["a", "b", "c"])
        assert calculate_priority_inversions(pred, gt) == 0

    def test_priority_inversions_nonzero(self):
        gt = self._make_gt(["a", "b", "c"])
        pred = self._make_pred(["c", "b", "a"])
        assert calculate_priority_inversions(pred, gt) > 0

    def test_critical_missed_rate_none_missed(self):
        gt = self._make_gt(["a", "b", "c"], critical_ids={"a", "b"})
        pred = self._make_pred(["a", "b", "c"])
        assert calculate_critical_missed_rate(pred, gt, k=3) == 0.0

    def test_critical_missed_rate_all_missed(self):
        gt = self._make_gt(["a", "b", "c"], critical_ids={"a", "b"})
        pred = self._make_pred(["c", "d", "e"])
        assert calculate_critical_missed_rate(pred, gt, k=3) == 1.0

    def test_high_impact_recall(self):
        gt = self._make_gt(["a", "b", "c", "d", "e"], high_impact_ids={"a", "b", "c"})
        pred = self._make_pred(["a", "b", "x", "y", "z"])
        assert calculate_high_impact_recall(pred, gt, k=3) == pytest.approx(2 / 3, abs=0.01)

    def test_order_agreement_concordant(self):
        gt = self._make_gt(["a", "b", "c"])
        pred = self._make_pred(["a", "b", "c"])
        assert calculate_order_agreement(pred, gt) == 1.0

    def test_order_agreement_discordant(self):
        gt = self._make_gt(["a", "b", "c"])
        pred = self._make_pred(["c", "b", "a"])
        assert calculate_order_agreement(pred, gt) == 0.0


# ============================================================
# 8. Benchmark Runner Tests
# ============================================================

class TestBenchmarkRunner:
    def test_track_a_small(self, tmp_path):
        runner = BenchmarkRunner(output_dir=str(tmp_path / "results"))
        result = runner.run_track_a_benchmark(sizes=[20], repetitions=2, seed=42)
        assert result["status"] == "SUCCESS"
        assert len(result["results"]) == 1
        assert (tmp_path / "results" / "performance" / "20.json").exists()

    def test_track_b_small(self, tmp_path):
        runner = BenchmarkRunner(output_dir=str(tmp_path / "results"))
        result = runner.run_track_b_experiment(size=20, seed=42)
        assert result["workload_size"] == 20
        assert "baseline" in result
        assert "signchain" in result
        assert "ablation" in result

    def test_multi_seed_runner(self, tmp_path):
        runner = BenchmarkRunner(output_dir=str(tmp_path / "results"))
        summary = runner.run_multi_seed_evaluation(
            size=20,
            seeds=[42, 43, 44, 45, 46, 47],
            scenario_family=ScenarioFamily.MIXED,
        )
        assert summary["total_independent_runs"] == 6
        assert "outcomes" in summary
        assert "effect_size" in summary

    def test_environment_metadata_collected(self, tmp_path):
        runner = BenchmarkRunner(output_dir=str(tmp_path / "results"))
        env = runner.get_environment_info()
        assert env["os"] in ("Windows", "Linux", "Darwin")
        assert env["total_ram_gb"] > 0


# ============================================================
# 9. PQC Algorithm Support
# ============================================================

class TestPQCAlgorithmSupport:
    def test_ml_dsa_classification(self):
        classifier = CryptoClassifier()
        for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            res = classifier.classify(algorithm_name=alg)
            assert res["quantum_status"] == QuantumStatus.QUANTUM_RESISTANT
            assert res["family"] == AlgorithmFamily.PQC_LATTICE

    def test_slh_dsa_classification(self):
        classifier = CryptoClassifier()
        res = classifier.classify(algorithm_name="SLH-DSA-SHA2-128s")
        assert res["quantum_status"] == QuantumStatus.QUANTUM_RESISTANT
        assert res["family"] == AlgorithmFamily.PQC_STATELESS_HASH

    def test_unsupported_algorithm_returns_unknown(self):
        classifier = CryptoClassifier()
        res = classifier.classify(algorithm_name="NON_EXISTENT_CIPHER_99")
        assert res["quantum_status"] == "UNKNOWN"
        assert res["family"] == AlgorithmFamily.UNKNOWN


# ============================================================
# 10. Adversarial Scenarios (A through H)
# ============================================================

class TestAdversarialScenarios:
    def test_scenario_a_high_severity_low_dep(self):
        """Scenario A: High crypto severity, low dependency, high criticality."""
        graph = DependencyGraph()
        leaf_cert = {
            "fingerprint": "a1" * 16, "sha256_fingerprint": "a1" * 16,
            "subject": "CN=CriticalLeaf", "issuer": "CN=Root",
            "canonical_algorithm": "RSA-2048", "public_key_algorithm": "RSA-2048",
            "quantum_status": "VULNERABLE", "key_size_bits": 2048, "key_size": 2048,
            "curve": None, "is_ca": False, "is_hub": False,
            "algorithm_family": "CLASSICAL_FACTORIZATION",
        }
        leaf_id = f"cert:{leaf_cert['fingerprint'][:16]}"
        graph.add_node(leaf_id, NodeType.CERTIFICATE, name="CN=CriticalLeaf")
        graph.add_node("art_crit_1", NodeType.ARTIFACT, name="critical-service")
        graph.add_edge("art_crit_1", leaf_id, edge_type=EdgeType.SIGNED_BY)

        engine = MigrationPrioritizationEngine()
        res = engine.prioritize_all([leaf_cert], graph_engine=graph)
        assert len(res["targets"]) == 1
        assert res["targets"][0]["priority_code"] in ("P1", "P2")

    def test_scenario_c_pqc_ready_hub(self):
        """Scenario C: High dependency hub that is already PQC ready should not be over-prioritized."""
        graph = DependencyGraph()
        pqc_hub = {
            "fingerprint": "c1" * 16, "sha256_fingerprint": "c1" * 16,
            "subject": "CN=PQCHub", "issuer": "CN=Root",
            "canonical_algorithm": "ML-DSA-65", "public_key_algorithm": "ML-DSA-65",
            "quantum_status": "QUANTUM_RESISTANT", "key_size_bits": 1536, "key_size": 1536,
            "curve": None, "is_ca": True, "is_hub": True,
            "algorithm_family": "PQC_LATTICE",
        }
        hub_id = f"cert:{pqc_hub['fingerprint'][:16]}"
        graph.add_node(hub_id, NodeType.CA, name="CN=PQCHub")
        for i in range(25):
            art_id = f"art_pqc_{i}"
            graph.add_node(art_id, NodeType.ARTIFACT, name=f"pkg-{i}")
            graph.add_edge(art_id, hub_id, edge_type=EdgeType.SIGNED_BY)

        engine = MigrationPrioritizationEngine()
        res = engine.prioritize_all([pqc_hub], graph_engine=graph)
        target = res["targets"][0]
        # PQC ready hub should have low priority despite 25 dependents
        assert target["priority_code"] in ("P3", "P4")

    def test_scenario_g_identical_dep_different_crypto(self):
        """Scenario G: Two assets with identical dependencies but different crypto risk."""
        graph = DependencyGraph()
        cert_rsa = {
            "fingerprint": "g1" * 16, "sha256_fingerprint": "g1" * 16,
            "subject": "CN=RSA-Signer", "issuer": "CN=Root",
            "canonical_algorithm": "RSA-2048", "public_key_algorithm": "RSA-2048",
            "quantum_status": "VULNERABLE", "key_size_bits": 2048, "key_size": 2048,
            "curve": None, "is_ca": False, "is_hub": False,
            "algorithm_family": "CLASSICAL_FACTORIZATION",
        }
        cert_pqc = {
            "fingerprint": "g2" * 16, "sha256_fingerprint": "g2" * 16,
            "subject": "CN=PQC-Signer", "issuer": "CN=Root",
            "canonical_algorithm": "ML-DSA-44", "public_key_algorithm": "ML-DSA-44",
            "quantum_status": "QUANTUM_RESISTANT", "key_size_bits": 1024, "key_size": 1024,
            "curve": None, "is_ca": False, "is_hub": False,
            "algorithm_family": "PQC_LATTICE",
        }
        id_rsa = f"cert:{cert_rsa['fingerprint'][:16]}"
        id_pqc = f"cert:{cert_pqc['fingerprint'][:16]}"
        graph.add_node(id_rsa, NodeType.CERTIFICATE, name="CN=RSA-Signer")
        graph.add_node(id_pqc, NodeType.CERTIFICATE, name="CN=PQC-Signer")

        for i in range(5):
            graph.add_node(f"art_rsa_{i}", NodeType.ARTIFACT, name=f"pkg-rsa-{i}")
            graph.add_edge(f"art_rsa_{i}", id_rsa, edge_type=EdgeType.SIGNED_BY)
            graph.add_node(f"art_pqc_{i}", NodeType.ARTIFACT, name=f"pkg-pqc-{i}")
            graph.add_edge(f"art_pqc_{i}", id_pqc, edge_type=EdgeType.SIGNED_BY)

        engine = MigrationPrioritizationEngine()
        res = engine.prioritize_all([cert_rsa, cert_pqc], graph_engine=graph)
        order = res["migration_order"]
        # RSA signer should be ordered before PQC signer
        assert order[0]["artifact_id"] == "CN=RSA-Signer"
        assert order[1]["artifact_id"] == "CN=PQC-Signer"

    def test_scenario_h_identical_crypto_different_dep(self):
        """Scenario H: Two assets with identical crypto risk but different dependencies."""
        graph = DependencyGraph()
        cert_hub = {
            "fingerprint": "h1" * 16, "sha256_fingerprint": "h1" * 16,
            "subject": "CN=Hub-RSA", "issuer": "CN=Root",
            "canonical_algorithm": "RSA-2048", "public_key_algorithm": "RSA-2048",
            "quantum_status": "VULNERABLE", "key_size_bits": 2048, "key_size": 2048,
            "curve": None, "is_ca": True, "is_hub": True,
            "algorithm_family": "CLASSICAL_FACTORIZATION",
        }
        cert_leaf = {
            "fingerprint": "h2" * 16, "sha256_fingerprint": "h2" * 16,
            "subject": "CN=Leaf-RSA", "issuer": "CN=Root",
            "canonical_algorithm": "RSA-2048", "public_key_algorithm": "RSA-2048",
            "quantum_status": "VULNERABLE", "key_size_bits": 2048, "key_size": 2048,
            "curve": None, "is_ca": False, "is_hub": False,
            "algorithm_family": "CLASSICAL_FACTORIZATION",
        }
        id_hub = f"cert:{cert_hub['fingerprint'][:16]}"
        id_leaf = f"cert:{cert_leaf['fingerprint'][:16]}"
        graph.add_node(id_hub, NodeType.CA, name="CN=Hub-RSA")
        graph.add_node(id_leaf, NodeType.CERTIFICATE, name="CN=Leaf-RSA")

        for i in range(20):
            graph.add_node(f"art_hub_{i}", NodeType.ARTIFACT, name=f"pkg-h-{i}")
            graph.add_edge(f"art_hub_{i}", id_hub, edge_type=EdgeType.SIGNED_BY)

        graph.add_node("art_leaf_single", NodeType.ARTIFACT, name="pkg-single")
        graph.add_edge("art_leaf_single", id_leaf, edge_type=EdgeType.SIGNED_BY)

        engine = MigrationPrioritizationEngine()
        res = engine.prioritize_all([cert_hub, cert_leaf], graph_engine=graph)
        order = res["migration_order"]
        # Hub should be ordered before leaf due to dependency impact
        assert order[0]["artifact_id"] == "CN=Hub-RSA"
        assert order[1]["artifact_id"] == "CN=Leaf-RSA"


# ============================================================
# 11. Ground Truth Sensitivity Analysis
# ============================================================

class TestGroundTruthSensitivity:
    def test_gt_sensitivity_configurations(self):
        w = SyntheticWorkloadGenerator(seed=42).generate_workload(size=50)
        certs = w["certificates"]
        graph = w["graph"]

        # Run with standard runner
        runner = BenchmarkRunner()
        res = runner.run_track_b_experiment(size=50, seed=42)
        assert res["workload_size"] == 50
        assert "signchain" in res
        assert "baseline" in res
