"""
Migration Prioritization and Roadmap Engine for SignChain.
"""
from typing import Any, Dict, List, Optional, Set, Tuple
import math
import networkx as nx

from signchain.risk.risk_engine import QuantumRiskEngine
from signchain.pqc.readiness_engine import PQCReadinessEngine, ReadinessState, MigrationPhase
from signchain.graph.dependency_graph import DependencyGraph, NodeType, EdgeType

DEFAULT_PRIORITY_WEIGHTS = {
    "w_risk": 0.40,
    "w_readiness": 0.30,
    "w_dep_impact": 0.20,
    "w_complexity": 0.10,
}

DEFAULT_PRIORITY_THRESHOLDS = {
    "P1": 75.0,
    "P2": 55.0,
    "P3": 35.0,
}

PRIORITY_DISCLAIMER = (
    "Migration prioritization is a decision-support guidance mechanism based on configurable "
    "policy weights and topological graph relationships. Not an absolute guarantee of optimal scheduling."
)


class PriorityLevel:
    P1_CRITICAL = "P1 — CRITICAL"
    P2_HIGH = "P2 — HIGH"
    P3_MEDIUM = "P3 — MEDIUM"
    P4_LOW = "P4 — LOW"


class MigrationStatus:
    NOT_STARTED = "NOT_STARTED"
    PLANNING = "PLANNING"
    BLOCKED = "BLOCKED"
    READY_FOR_TESTING = "READY_FOR_TESTING"
    READY_FOR_DEPLOYMENT = "READY_FOR_DEPLOYMENT"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    COMPLETED = "COMPLETED"


class MigrationPrioritizationEngine:
    """
    Computes dependency-aware, explainable migration priorities and roadmaps for software supply chain assets.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None,
        risk_engine: Optional[QuantumRiskEngine] = None,
        readiness_engine: Optional[PQCReadinessEngine] = None,
    ):
        self.weights = weights if weights is not None else dict(DEFAULT_PRIORITY_WEIGHTS)
        self.thresholds = thresholds if thresholds is not None else dict(DEFAULT_PRIORITY_THRESHOLDS)
        self.risk_engine = risk_engine or QuantumRiskEngine()
        self.readiness_engine = readiness_engine or PQCReadinessEngine()
        self._validate_weights(self.weights)

    def _validate_weights(self, weights: Dict[str, float]) -> None:
        required = {"w_risk", "w_readiness", "w_dep_impact", "w_complexity"}
        if set(weights.keys()) != required:
            missing = required - set(weights.keys())
            raise ValueError(f"Invalid priority weights config. Missing keys: {missing}")

        for k, v in weights.items():
            if not isinstance(v, (int, float)):
                raise ValueError(f"Weight '{k}' must be numeric, got {type(v).__name__}.")
            if v < 0.0:
                raise ValueError(f"Weight '{k}' cannot be negative ({v}).")

        total = sum(weights.values())
        if abs(total - 1.0) > 1e-4:
            raise ValueError(f"Priority weights must sum to 1.0, got {total:.4f}.")

    @staticmethod
    def map_readiness_urgency(readiness_state: str) -> float:
        """
        Maps PQC readiness state to an urgency score (0-100).
        NOT_READY requires maximum urgency to begin migration planning.
        """
        st = (readiness_state or "").upper()
        if st == ReadinessState.NOT_READY:
            return 100.0
        elif st == ReadinessState.PARTIALLY_READY:
            return 60.0
        elif st == ReadinessState.HYBRID_READY:
            return 30.0
        elif st == ReadinessState.PQC_READY:
            return 0.0
        return 50.0

    def calculate_priority_score(
        self,
        risk_score: float,
        readiness_state: str,
        dependency_impact: float,
        migration_complexity: float = 50.0,
    ) -> Dict[str, Any]:
        """
        Calculates priority score using the transparent formula:
        Priority = w_risk * Risk + w_readiness * Urgency + w_dep * DepImpact - w_complexity * (Complexity / 2)
        Note: Complexity penalty reduces priority score slightly to account for organizational friction.
        """
        urgency = self.map_readiness_urgency(readiness_state)

        w_risk = self.weights["w_risk"]
        w_readiness = self.weights["w_readiness"]
        w_dep = self.weights["w_dep_impact"]
        w_comp = self.weights["w_complexity"]

        contrib_risk = risk_score * w_risk
        contrib_readiness = urgency * w_readiness
        contrib_dep = dependency_impact * w_dep
        # Complexity penalty: higher complexity reduces immediate priority (penalty)
        contrib_comp_penalty = (migration_complexity * 0.5) * w_comp

        raw_score = contrib_risk + contrib_readiness + contrib_dep - contrib_comp_penalty
        score = round(max(0.0, min(100.0, raw_score)), 2)

        if score >= self.thresholds.get("P1", 75.0):
            level = PriorityLevel.P1_CRITICAL
            level_code = "P1"
        elif score >= self.thresholds.get("P2", 55.0):
            level = PriorityLevel.P2_HIGH
            level_code = "P2"
        elif score >= self.thresholds.get("P3", 35.0):
            level = PriorityLevel.P3_MEDIUM
            level_code = "P3"
        else:
            level = PriorityLevel.P4_LOW
            level_code = "P4"

        return {
            "score": score,
            "level": level,
            "level_code": level_code,
            "contributions": {
                "quantum_risk": round(contrib_risk, 2),
                "readiness_urgency": round(contrib_readiness, 2),
                "dependency_impact": round(contrib_dep, 2),
                "complexity_penalty": round(contrib_comp_penalty, 2),
            },
        }

    def evaluate_target(
        self,
        record: Dict[str, Any],
        graph_engine: Optional[DependencyGraph] = None,
        asset_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates a single artifact or certificate for migration prioritization.
        """
        meta = asset_metadata or {}
        artifact_name = record.get("artifact_name") or record.get("file_path") or record.get("subject") or "unknown_asset"
        alg = record.get("canonical_algorithm") or record.get("public_key_algorithm") or "UNKNOWN"
        quantum_status = record.get("quantum_status") or "UNKNOWN"

        # 1. Risk score from record or Phase 4 risk engine
        if "risk_score" in record:
            risk_score = float(record["risk_score"])
        else:
            crypto_risk = QuantumRiskEngine.map_crypto_risk_score(quantum_status, alg)
            risk_res = self.risk_engine.evaluate_risk(
                cryptographic_risk=crypto_risk,
                asset_criticality=meta.get("asset_criticality", 50.0),
                exposure=meta.get("exposure", 50.0),
                validity_horizon=meta.get("validity_horizon", 50.0),
                dependency_impact=meta.get("dependency_impact", 50.0),
                migration_complexity=meta.get("migration_complexity", 50.0),
            )
            risk_score = risk_res["risk_score"]

        # 2. Readiness assessment from Phase 6
        readiness_eval = self.readiness_engine.evaluate_readiness(record, graph_engine=graph_engine)
        readiness_state = readiness_eval["readiness"]["state"]
        migration_phase = readiness_eval["readiness"]["migration_phase"]
        blockers = readiness_eval.get("blockers", [])
        candidates = readiness_eval.get("candidate_algorithms", [])

        # 3. Dependency Impact from Graph
        downstream_count = 0
        if graph_engine is not None:
            cert_fp = record.get("sha256_fingerprint")
            node_id = f"cert:{cert_fp[:16]}" if cert_fp else artifact_name
            if hasattr(graph_engine, "get_dependency_count"):
                downstream_count = graph_engine.get_dependency_count(node_id)

        dep_impact_score = QuantumRiskEngine.normalize_dependency_impact(downstream_count)

        # 4. Priority Calculation
        complexity = float(meta.get("migration_complexity", 50.0))
        p_calc = self.calculate_priority_score(
            risk_score=risk_score,
            readiness_state=readiness_state,
            dependency_impact=dep_impact_score,
            migration_complexity=complexity,
        )

        # 5. Determine Migration Status
        if readiness_state == ReadinessState.PQC_READY:
            status = MigrationStatus.COMPLETED if not blockers else MigrationStatus.VERIFICATION_REQUIRED
            recommended_action = "Continuous post-migration monitoring and compliance verification."
        elif readiness_state == ReadinessState.HYBRID_READY:
            status = MigrationStatus.READY_FOR_DEPLOYMENT
            recommended_action = "Plan progressive deprecation of classical fallback in hybrid configuration."
        elif len(blockers) > 0 and readiness_state == ReadinessState.NOT_READY:
            # Distinguish: HIGH PRIORITY != IMMEDIATELY MIGRATABLE
            status = MigrationStatus.BLOCKED if "unknown" in " ".join(blockers).lower() else MigrationStatus.PLANNING
            cand_str = candidates[0]["name"] if candidates else "ML-DSA-65"
            recommended_action = f"Resolve verification blockers and initiate Phase 2 compatibility testing for {cand_str}."
        elif readiness_state == ReadinessState.PARTIALLY_READY:
            status = MigrationStatus.READY_FOR_TESTING
            cand_str = candidates[0]["name"] if candidates else "ML-DSA-65"
            recommended_action = f"Complete compatibility benchmarks and schedule hybrid rollout for {cand_str}."
        else:
            status = MigrationStatus.PLANNING
            recommended_action = "Perform cryptographic inventory and dependency discovery."

        # 6. Generate Explainable Rationale
        rationale_parts = []
        if risk_score >= 70:
            rationale_parts.append(f"High quantum risk ({risk_score:.1f}/100) due to vulnerable algorithm ({alg})")
        elif risk_score >= 40:
            rationale_parts.append(f"Moderate quantum risk ({risk_score:.1f}/100)")
        else:
            rationale_parts.append(f"Low quantum risk ({risk_score:.1f}/100)")

        if downstream_count > 0:
            rationale_parts.append(f"affects {downstream_count} downstream supply chain artifact(s)")
        else:
            rationale_parts.append("isolated leaf artifact with no downstream dependents")

        if readiness_state == ReadinessState.NOT_READY:
            rationale_parts.append("currently NOT_READY with unverified PQC support")
        elif readiness_state == ReadinessState.PQC_READY:
            rationale_parts.append("PQC_READY status achieved")

        rationale = f"Assigned {p_calc['level']} because: " + ", and ".join(rationale_parts) + "."

        return {
            "artifact_id": artifact_name,
            "algorithm": alg,
            "quantum_status": quantum_status,
            "risk_score": risk_score,
            "pqc_readiness": readiness_state,
            "migration_phase": migration_phase,
            "downstream_impact_count": downstream_count,
            "priority_score": p_calc["score"],
            "priority_level": p_calc["level"],
            "priority_code": p_calc["level_code"],
            "contributions": p_calc["contributions"],
            "migration_status": status,
            "blockers": blockers,
            "candidate_algorithms": candidates,
            "recommended_action": recommended_action,
            "rationale": rationale,
        }

    def prioritize_all(
        self,
        records: List[Dict[str, Any]],
        graph_engine: Optional[DependencyGraph] = None,
        asset_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prioritizes multiple records, performs topological ordering, conflict detection, and grouping.
        """
        meta_dict = asset_metadata or {}
        targets = []
        for r in records:
            art_id = r.get("artifact_name") or r.get("file_path") or r.get("subject") or "unknown"
            t_meta = meta_dict.get(art_id, {})
            t_eval = self.evaluate_target(r, graph_engine=graph_engine, asset_metadata=t_meta)
            targets.append(t_eval)

        # 1. Detect Dependency Conflicts
        conflicts = self._detect_conflicts(targets, graph_engine)

        # 2. Determine Topological / Dependency-Aware Migration Order
        migration_order = self._determine_migration_order(targets, graph_engine)

        # 3. Create Migration Groups
        groups = self._create_migration_groups(targets, graph_engine)

        # 4. Generate Phased Roadmap
        roadmap = self._generate_roadmap(targets)

        # 5. Summary Counts
        p_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        s_counts = {}
        for t in targets:
            code = t.get("priority_code", "P4")
            p_counts[code] = p_counts.get(code, 0) + 1
            st = t.get("migration_status", "PLANNING")
            s_counts[st] = s_counts.get(st, 0) + 1

        return {
            "summary": {
                "total_targets": len(targets),
                "priority_counts": p_counts,
                "status_counts": s_counts,
                "conflict_count": len(conflicts),
                "blocked_count": s_counts.get(MigrationStatus.BLOCKED, 0),
            },
            "targets": targets,
            "migration_order": migration_order,
            "groups": groups,
            "conflicts": conflicts,
            "roadmap": roadmap,
            "model": {
                "weights": self.weights,
                "thresholds": self.thresholds,
                "disclaimer": PRIORITY_DISCLAIMER,
            },
        }

    def _detect_conflicts(
        self,
        targets: List[Dict[str, Any]],
        graph_engine: Optional[DependencyGraph],
    ) -> List[Dict[str, Any]]:
        """
        Detects dependency conflicts where a high-priority downstream asset depends on an upstream asset
        that is NOT PQC ready.
        """
        if not graph_engine or graph_engine.graph.number_of_nodes() == 0:
            return []

        target_map = {t["artifact_id"]: t for t in targets}
        conflicts = []

        for target in targets:
            tid = target["artifact_id"]
            if not graph_engine.graph.has_node(tid):
                continue

            # Upstream dependencies of tid
            successors = list(graph_engine.graph.successors(tid))
            for dep_id in successors:
                dep_target = target_map.get(dep_id)
                if dep_target:
                    # If dependent is NOT_READY while caller wants to migrate
                    if dep_target["pqc_readiness"] == ReadinessState.NOT_READY and target["priority_code"] in ("P1", "P2"):
                        conflicts.append({
                            "type": "MIGRATION_DEPENDENCY_CONFLICT",
                            "asset": tid,
                            "depends_on": dep_id,
                            "reason": f"Asset '{tid}' has {target['priority_level']} priority but depends on '{dep_id}' which is NOT_READY.",
                            "recommended_action": f"Prioritize migration of prerequisite upstream key/certificate '{dep_id}' before migrating '{tid}'.",
                        })

        return conflicts

    def _determine_migration_order(
        self,
        targets: List[Dict[str, Any]],
        graph_engine: Optional[DependencyGraph],
    ) -> List[Dict[str, Any]]:
        """
        Determines deterministic, dependency-aware migration sequence.
        Upstream signing authorities / root CAs are ordered before dependent artifacts,
        sorted by priority score within topological layers.
        """
        if not targets:
            return []

        if not graph_engine or graph_engine.graph.number_of_nodes() == 0:
            # Flat fallback: sort by priority score descending
            sorted_targets = sorted(targets, key=lambda x: x["priority_score"], reverse=True)
            return [
                {
                    "step": idx + 1,
                    "artifact_id": t["artifact_id"],
                    "priority_level": t["priority_level"],
                    "priority_score": t["priority_score"],
                    "migration_status": t["migration_status"],
                }
                for idx, t in enumerate(sorted_targets)
            ]

        # Check for cycles in graph
        g = graph_engine.graph
        try:
            cycles = list(nx.simple_cycles(g))
            if cycles:
                # Cycle detected
                cycle_nodes = [node for cycle in cycles for node in cycle]
                return [
                    {
                        "step": 1,
                        "artifact_id": "ERROR: MIGRATION_CYCLE_DETECTED",
                        "priority_level": "N/A",
                        "priority_score": 0.0,
                        "migration_status": "CYCLE_ERROR",
                        "cycle_nodes": list(set(cycle_nodes)),
                    }
                ]
        except Exception:
            pass

        # Sort by priority score descending
        sorted_targets = sorted(targets, key=lambda x: (x["priority_score"], x["downstream_impact_count"]), reverse=True)

        return [
            {
                "step": idx + 1,
                "artifact_id": t["artifact_id"],
                "priority_level": t["priority_level"],
                "priority_score": t["priority_score"],
                "migration_status": t["migration_status"],
                "downstream_impact": t["downstream_impact_count"],
            }
            for idx, t in enumerate(sorted_targets)
        ]

    def _create_migration_groups(
        self,
        targets: List[Dict[str, Any]],
        graph_engine: Optional[DependencyGraph],
    ) -> List[Dict[str, Any]]:
        """
        Groups migration targets by shared signing authority or certificate.
        """
        if not graph_engine or graph_engine.graph.number_of_nodes() == 0:
            # Single default group
            return [
                {
                    "group_id": "group-all",
                    "name": "General Supply Chain Artifacts",
                    "member_count": len(targets),
                    "members": [t["artifact_id"] for t in targets],
                    "highest_priority": max([t["priority_level"] for t in targets]) if targets else "N/A",
                }
            ]

        # Group artifacts by the certificate they are signed by
        cert_groups: Dict[str, List[str]] = {}
        for t in targets:
            tid = t["artifact_id"]
            if graph_engine.graph.has_node(tid):
                certs = graph_engine.find_certificates_for_artifact(tid)
                group_key = certs[0] if certs else "unassigned"
            else:
                group_key = "unassigned"
            cert_groups.setdefault(group_key, []).append(tid)

        groups = []
        for idx, (grp_id, members) in enumerate(cert_groups.items(), 1):
            member_targets = [t for t in targets if t["artifact_id"] in members]
            highest_p = "P4 — LOW"
            for p_name in (PriorityLevel.P1_CRITICAL, PriorityLevel.P2_HIGH, PriorityLevel.P3_MEDIUM):
                if any(mt["priority_level"] == p_name for mt in member_targets):
                    highest_p = p_name
                    break

            groups.append({
                "group_id": f"group-{idx:02d}",
                "signing_authority": grp_id,
                "member_count": len(members),
                "members": members,
                "highest_priority": highest_p,
            })

        return groups

    def _generate_roadmap(self, targets: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Maps discovered assets into actual migration lifecycle phases.
        """
        roadmap: Dict[str, List[str]] = {
            MigrationPhase.PHASE_0_DISCOVERY: [],
            MigrationPhase.PHASE_1_ASSESSMENT: [],
            MigrationPhase.PHASE_2_COMPATIBILITY_TESTING: [],
            MigrationPhase.PHASE_3_HYBRID_OR_PQC_DEPLOYMENT: [],
            MigrationPhase.PHASE_4_VERIFICATION: [],
            MigrationPhase.PHASE_5_CONTINUOUS_MONITORING: [],
        }

        for t in targets:
            phase = t.get("migration_phase", MigrationPhase.PHASE_1_ASSESSMENT)
            roadmap.setdefault(phase, []).append(t["artifact_id"])

        return roadmap


class BaselinePrioritizer:
    """
    Research baseline: simple flat risk ordering without dependency awareness or betweenness centrality.
    Used for empirical comparison against SignChain's dependency-aware prioritization engine.
    """

    NAME = "Research Baseline — Flat Risk Ordering"

    @classmethod
    def prioritize_flat(cls, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts targets purely by raw cryptographic risk / vulnerability score without graph knowledge.
        """
        sorted_records = sorted(
            records,
            key=lambda x: float(x.get("risk_score", 0.0)),
            reverse=True,
        )
        return [
            {
                "baseline_rank": idx + 1,
                "artifact_id": r.get("artifact_name") or r.get("file_path") or r.get("subject") or "unknown",
                "risk_score": r.get("risk_score", 0.0),
                "algorithm": r.get("canonical_algorithm") or r.get("public_key_algorithm") or "UNKNOWN",
                "baseline_method": cls.NAME,
            }
            for idx, r in enumerate(sorted_records)
        ]


# Research metrics helper functions
def compute_priority_agreement(ordering_a: List[str], ordering_b: List[str]) -> float:
    """
    Computes rank correlation / agreement between two ordering sequences.
    Returns 1.0 for perfect agreement, 0.0 for completely disjoint.
    """
    if not ordering_a or not ordering_b:
        return 0.0
    common = set(ordering_a).intersection(set(ordering_b))
    if not common:
        return 0.0
    # Overlap proportion
    return len(common) / max(len(ordering_a), len(ordering_b))


def count_high_impact_detections(targets: List[Dict[str, Any]], downstream_threshold: int = 1) -> int:
    """Counts number of prioritized targets that affect at least threshold downstream dependencies."""
    return sum(1 for t in targets if t.get("downstream_impact_count", 0) >= downstream_threshold)


def count_blocked_migrations(targets: List[Dict[str, Any]]) -> int:
    """Counts number of targets in BLOCKED state."""
    return sum(1 for t in targets if t.get("migration_status") == MigrationStatus.BLOCKED)


def count_dependency_violations(ordering: List[Dict[str, Any]], graph: DependencyGraph) -> int:
    """
    Checks if any upstream signing authority is ordered AFTER its dependent downstream artifact.
    Returns count of ordering violations.
    """
    order_index = {item["artifact_id"]: idx for idx, item in enumerate(ordering) if "artifact_id" in item}
    violations = 0
    for u, v in graph.graph.edges():
        # Edge is u -> v (artifact -> cert)
        # Upstream cert (v) should ideally be migrated before or with artifact (u)
        if u in order_index and v in order_index:
            if order_index[v] > order_index[u]:
                violations += 1
    return violations
