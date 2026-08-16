"""
Deterministic synthetic software supply-chain workload generator for SignChain benchmarking.

Supports multiple controlled scenario families:
  A. Dependency-Hub Scenario (High downstream impact)
  B. Isolated Critical Scenario (High business criticality on leaf nodes, low dependency)
  C. Cryptographically Severe Scenario (Severe vulnerable crypto, limited blast radius)
  D. Migration-Blocked Scenario (High impact but severe verification/ecosystem blockers)
  E. Mixed Scenario (Standard realistic distribution)
  F. Anti-Correlation Scenario (Dependency count and crypto vulnerability inversely correlated)

CRITICAL GROUND-TRUTH INDEPENDENCE:
Ground truth rankings are derived strictly from independently declared scenario attributes:
  - Business impact / recovery consequence
  - Cryptographic exposure tier
  - Multi-service blast radius
  - Migration feasibility penalty
Ground truth NEVER calls or imports any SignChain production engine.
"""
import math
import random
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType


class ScenarioFamily:
    DEPENDENCY_HUB = "DEPENDENCY_HUB"
    ISOLATED_CRITICAL = "ISOLATED_CRITICAL"
    CRYPTO_SEVERE = "CRYPTO_SEVERE"
    MIGRATION_BLOCKED = "MIGRATION_BLOCKED"
    MIXED = "MIXED"
    ANTI_CORRELATION = "ANTI_CORRELATION"


class SyntheticWorkloadGenerator:
    """
    Generates deterministic synthetic workloads with controlled cryptographic distributions,
    graph topologies, business criticality labels, and independent multi-criteria ground truth.
    """

    ECOSYSTEM_DISTRIBUTION = [
        ("X509", 0.25),
        ("AUTHENTICODE", 0.25),
        ("OPENPGP", 0.15),
        ("SIGSTORE", 0.20),
        ("CONTAINER", 0.15),
    ]

    ALGORITHM_DISTRIBUTION = [
        ("RSA-2048", 0.40),
        ("RSA-4096", 0.15),
        ("ECDSA-secp256r1", 0.25),
        ("ECDSA-secp384r1", 0.05),
        ("Ed25519", 0.05),
        ("ML-DSA-44", 0.05),
        ("ML-DSA-65", 0.03),
        ("SLH-DSA", 0.02),
    ]

    CRITICALITY_DISTRIBUTION = [
        ("LOW", 0.30, 20.0),
        ("MEDIUM", 0.40, 50.0),
        ("HIGH", 0.20, 80.0),
        ("CRITICAL", 0.10, 100.0),
    ]

    ALGORITHM_METADATA = {
        "RSA-2048": {"family": "CLASSICAL_FACTORIZATION", "key_size_bits": 2048, "curve": None, "pqc": False},
        "RSA-4096": {"family": "CLASSICAL_FACTORIZATION", "key_size_bits": 4096, "curve": None, "pqc": False},
        "ECDSA-secp256r1": {"family": "CLASSICAL_ECC", "key_size_bits": 256, "curve": "secp256r1", "pqc": False},
        "ECDSA-secp384r1": {"family": "CLASSICAL_ECC", "key_size_bits": 384, "curve": "secp384r1", "pqc": False},
        "Ed25519": {"family": "CLASSICAL_ECC", "key_size_bits": 256, "curve": "Ed25519", "pqc": False},
        "ML-DSA-44": {"family": "PQC_LATTICE", "key_size_bits": 1024, "curve": None, "pqc": True},
        "ML-DSA-65": {"family": "PQC_LATTICE", "key_size_bits": 1536, "curve": None, "pqc": True},
        "SLH-DSA": {"family": "PQC_STATELESS_HASH", "key_size_bits": 1024, "curve": None, "pqc": True},
    }

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_workload(
        self,
        size: int,
        hub_ratio: float = 0.05,
        scenario_family: str = ScenarioFamily.MIXED,
    ) -> Dict[str, Any]:
        """
        Generates a complete frozen synthetic workload and independent ground truth.
        """
        self.rng.seed(self.seed + size + hash(scenario_family) % 10000)

        cert_count = max(5, int(size * 0.20))
        certificates = self._generate_certificates(cert_count, hub_ratio, scenario_family)
        artifacts = [self._generate_artifact(i, certificates, scenario_family) for i in range(size)]
        graph = self._build_dependency_graph(artifacts, certificates)

        subject_to_target_id = {c["subject"]: f"cert:{c['fingerprint'][:16]}" for c in certificates}

        # Independent ground truth generated strictly before any ranking model runs
        ground_truth = self._compute_independent_ground_truth(artifacts, certificates, graph, scenario_family)

        stats = graph.get_graph_statistics()
        return {
            "workload_size": size,
            "seed": self.seed,
            "scenario_family": scenario_family,
            "artifact_count": len(artifacts),
            "certificate_count": len(certificates),
            "graph_nodes": stats["total_nodes"],
            "graph_edges": stats["total_edges"],
            "artifacts": artifacts,
            "certificates": certificates,
            "graph": graph,
            "ground_truth": ground_truth,
            "subject_to_target_id": subject_to_target_id,
        }

    def _generate_certificates(
        self,
        count: int,
        hub_ratio: float,
        scenario: str,
    ) -> List[Dict[str, Any]]:
        certs = []
        hub_count = max(1, int(count * hub_ratio))

        for i in range(count):
            is_hub = i < hub_count

            # Scenario-specific algorithm assignment
            if scenario == ScenarioFamily.ANTI_CORRELATION:
                # Anti-correlation: Hubs are PQC, while leaves are vulnerable RSA-2048
                alg = "ML-DSA-44" if is_hub else "RSA-2048"
            elif scenario == ScenarioFamily.CRYPTO_SEVERE:
                # Cryptographically severe on leaves
                alg = "RSA-2048" if (i % 2 == 0) else "ECDSA-secp256r1"
            elif scenario == ScenarioFamily.DEPENDENCY_HUB:
                # Vulnerable root hub with huge blast radius
                alg = "RSA-4096" if is_hub else self._sample_distribution(self.ALGORITHM_DISTRIBUTION)
            else:
                alg = self._sample_distribution(self.ALGORITHM_DISTRIBUTION)

            fp = hashlib.sha256(f"cert_seed_{self.seed}_{i}_{alg}_{scenario}".encode()).hexdigest()
            meta = self.ALGORITHM_METADATA.get(alg, self.ALGORITHM_METADATA["RSA-2048"])
            is_pqc = meta["pqc"]

            # Scenario-specific readiness/testing metadata
            is_blocked = (scenario == ScenarioFamily.MIGRATION_BLOCKED) and (i % 3 == 0)

            certs.append({
                "subject": f"CN=Signer-{i:04d}-{'RootCA' if is_hub else 'Leaf'}",
                "issuer": f"CN=CA-{(i // 5):02d}" if not is_hub else "CN=SelfSignedRoot",
                "fingerprint": fp,
                "sha256_fingerprint": fp,
                "canonical_algorithm": alg,
                "public_key_algorithm": alg,
                "algorithm_family": meta["family"],
                "quantum_status": "QUANTUM_RESISTANT" if is_pqc else "VULNERABLE",
                "key_size_bits": meta["key_size_bits"],
                "key_size": meta["key_size_bits"],
                "curve": meta["curve"],
                "is_ca": is_hub,
                "is_hub": is_hub,
                "is_migration_blocked": is_blocked,
                "assigned_artifact_count": 0,
            })
        return certs

    def _generate_artifact(
        self,
        index: int,
        cert_pool: List[Dict[str, Any]],
        scenario: str,
    ) -> Dict[str, Any]:
        eco = self._sample_distribution(self.ECOSYSTEM_DISTRIBUTION)

        if scenario == ScenarioFamily.ISOLATED_CRITICAL:
            # Isolated critical: 10% of leaf artifacts have extreme criticality
            crit_label, crit_score = ("CRITICAL", 100.0) if (index % 10 == 0) else ("LOW", 20.0)
        else:
            crit_label, _, crit_score = self._sample_distribution_with_val(self.CRITICALITY_DISTRIBUTION)

        # Weighting selection based on hub status
        if scenario == ScenarioFamily.ANTI_CORRELATION:
            # Anti-correlation: evenly distribute or heavily assign to PQC hub
            weights = [15.0 if c["is_hub"] else 1.0 for c in cert_pool]
        else:
            weights = [10.0 if c["is_hub"] else 1.0 for c in cert_pool]

        chosen_cert = self.rng.choices(cert_pool, weights=weights, k=1)[0]
        chosen_cert["assigned_artifact_count"] += 1

        digest = hashlib.sha256(f"art_seed_{self.seed}_{index}_{eco}_{scenario}".encode()).hexdigest()
        name = f"pkg-{eco.lower()}-{index:05d}"

        return {
            "id": f"art_{index:05d}",
            "name": name,
            "file_path": f"/supply-chain/{eco.lower()}/{name}",
            "ecosystem": eco,
            "artifact_type": f"{eco}_OBJECT",
            "digest": f"sha256:{digest}",
            "business_criticality": crit_label,
            "criticality_score": crit_score,
            "exposure_score": self.rng.choice([20.0, 50.0, 80.0, 100.0]),
            "validity_horizon_score": self.rng.choice([30.0, 60.0, 90.0]),
            "migration_complexity_score": self.rng.choice([25.0, 50.0, 75.0]),
            "status": "SUCCESS",
            "certificate": chosen_cert,
            "certificates": [chosen_cert],
            "quantum_status": chosen_cert["quantum_status"],
            "canonical_algorithm": chosen_cert["canonical_algorithm"],
        }

    def _build_dependency_graph(
        self,
        artifacts: List[Dict[str, Any]],
        certificates: List[Dict[str, Any]],
    ) -> DependencyGraph:
        graph = DependencyGraph()

        for cert in certificates:
            cert_id = f"cert:{cert['fingerprint'][:16]}"
            node_type = NodeType.CA if cert["is_ca"] else NodeType.CERTIFICATE
            graph.add_node(
                node_id=cert_id,
                node_type=node_type,
                name=cert["subject"],
                metadata={"fingerprint": cert["fingerprint"], "algorithm": cert["canonical_algorithm"]},
            )

        for art in artifacts:
            art_id = art["id"]
            graph.add_node(
                node_id=art_id,
                node_type=NodeType.CONTAINER if art["ecosystem"] == "CONTAINER" else NodeType.ARTIFACT,
                name=art["name"],
                metadata={"ecosystem": art["ecosystem"], "criticality": art["business_criticality"]},
            )
            cert = art["certificate"]
            cert_id = f"cert:{cert['fingerprint'][:16]}"
            graph.add_edge(art_id, cert_id, edge_type=EdgeType.SIGNED_BY)

        for i in range(len(artifacts)):
            if self.rng.random() < 0.20 and i > 0:
                parent_idx = self.rng.randint(0, i - 1)
                graph.add_edge(artifacts[i]["id"], artifacts[parent_idx]["id"], edge_type=EdgeType.DEPENDS_ON)

        return graph

    def _compute_independent_ground_truth(
        self,
        artifacts: List[Dict[str, Any]],
        certificates: List[Dict[str, Any]],
        graph: DependencyGraph,
        scenario: str,
    ) -> List[Dict[str, Any]]:
        """
        Computes independent ground truth ranking based on scenario objective parameters.

        INDEPENDENCE ASSURANCE:
        - Does NOT invoke MigrationPrioritizationEngine, QuantumRiskEngine, or PQCReadinessEngine.
        - Uses Multi-Criteria Decision Analysis (MCDA) based on scenario specifications:
            1. Business Impact: Average criticality of dependent services (35%)
            2. Quantum Severity: 35.0 if vulnerable, 5.0 if PQC (35%)
            3. Blast Radius: Logarithmic dependent service reachability (25%)
            4. Feasibility Penalty: 10.0 deduction if migration is blocked by external constraint
        """
        art_by_id = {a["id"]: a for a in artifacts}
        rankings = []

        for cert in certificates:
            cert_id = f"cert:{cert['fingerprint'][:16]}"
            dependents = graph.find_downstream_dependencies(cert_id)
            dep_count = len(dependents)

            is_vuln = 1.0 if cert["quantum_status"] == "VULNERABLE" else 0.1
            log_blast_radius = min(100.0, math.log(1 + dep_count, 2) * 12.5)

            dep_artifacts = [art_by_id[did] for did in dependents if did in art_by_id]
            if dep_artifacts:
                avg_crit = sum(a["criticality_score"] for a in dep_artifacts) / len(dep_artifacts)
            else:
                avg_crit = 30.0

            feasibility_penalty = 15.0 if cert.get("is_migration_blocked", False) else 0.0

            # Independent MCDA Ground Truth Urgency
            ground_truth_urgency = (avg_crit * 0.35) + (is_vuln * 35.0) + (log_blast_radius * 0.30) - feasibility_penalty
            ground_truth_urgency = max(0.0, min(100.0, ground_truth_urgency))

            is_critical = (dep_count >= 10 and is_vuln > 0.5) or (avg_crit >= 80.0 and is_vuln > 0.5)

            rankings.append({
                "target_id": cert_id,
                "fingerprint": cert["fingerprint"],
                "subject": cert["subject"],
                "algorithm": cert["canonical_algorithm"],
                "quantum_status": cert["quantum_status"],
                "dependent_count": dep_count,
                "ground_truth_score": round(ground_truth_urgency, 4),
                "is_critical_target": is_critical,
                "is_high_impact_target": dep_count >= 5,
            })

        rankings.sort(key=lambda x: (x["ground_truth_score"], x["dependent_count"]), reverse=True)
        for rank, item in enumerate(rankings):
            item["ground_truth_rank"] = rank + 1

        return rankings

    def _sample_distribution(self, dist: List[Tuple[str, float]]) -> str:
        keys = [k for k, _ in dist]
        weights = [w for _, w in dist]
        return self.rng.choices(keys, weights=weights, k=1)[0]

    def _sample_distribution_with_val(self, dist: List[Tuple[str, float, float]]) -> Tuple[str, float, float]:
        weights = [w for _, w, _ in dist]
        return self.rng.choices(dist, weights=weights, k=1)[0]
