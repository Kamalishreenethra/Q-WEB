"""
PQC Readiness Assessment Engine for SignChain.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from signchain.pqc.knowledge_base import PQCKnowledgeBase

READINESS_DISCLAIMER = (
    "PQC readiness assessment is an automated decision-support guidance mechanism and "
    "does not constitute a guarantee of future security or compliance."
)


class ReadinessState:
    NOT_READY = "NOT_READY"
    PARTIALLY_READY = "PARTIALLY_READY"
    HYBRID_READY = "HYBRID_READY"
    PQC_READY = "PQC_READY"
    UNKNOWN = "UNKNOWN"


class MigrationPhase:
    PHASE_0_DISCOVERY = "PHASE_0_DISCOVERY"
    PHASE_1_ASSESSMENT = "PHASE_1_ASSESSMENT"
    PHASE_2_COMPATIBILITY_TESTING = "PHASE_2_COMPATIBILITY_TESTING"
    PHASE_3_HYBRID_OR_PQC_DEPLOYMENT = "PHASE_3_HYBRID_OR_PQC_DEPLOYMENT"
    PHASE_4_VERIFICATION = "PHASE_4_VERIFICATION"
    PHASE_5_CONTINUOUS_MONITORING = "PHASE_5_CONTINUOUS_MONITORING"


class CompatibilityStatus:
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class EvidenceLevel:
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class PQCReadinessEngine:
    """
    Evaluates evidence-based PQC readiness, candidate migration targets, blockers, and migration phases.
    """

    def __init__(self, knowledge_base: Optional[PQCKnowledgeBase] = None):
        self.kb = knowledge_base or PQCKnowledgeBase()

    def evaluate_readiness(
        self,
        cert_or_scan_record: Dict[str, Any],
        graph_engine: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates readiness state, candidates, compatibility dimensions, evidence, blockers, and phase.
        """
        if not cert_or_scan_record or not isinstance(cert_or_scan_record, dict):
            return self._build_unknown_assessment("Invalid or empty input record.")

        # Check if input is a scan container object containing list of certs
        if "certificates" in cert_or_scan_record and isinstance(cert_or_scan_record["certificates"], list):
            certs = cert_or_scan_record["certificates"]
            if not certs:
                return self._build_unknown_assessment("No certificates found in scan result.")
            target_record = certs[0]
        else:
            target_record = cert_or_scan_record

        status = target_record.get("status")
        if status == "ERROR":
            return self._build_unknown_assessment(target_record.get("error_message", "Scan error."))

        quantum_status = (target_record.get("quantum_status") or "UNKNOWN").upper()
        canonical_alg = target_record.get("canonical_algorithm") or target_record.get("public_key_algorithm") or "UNKNOWN"
        algorithm_family = target_record.get("algorithm_family") or "UNKNOWN"
        artifact_name = target_record.get("artifact_name") or target_record.get("file_path") or "unknown_artifact"
        fmt = target_record.get("format", "X.509")

        # 1. Candidate Migration Options (using algorithm family for precise matching)
        candidates = self.kb.get_recommended_candidates(canonical_alg, algorithm_family=algorithm_family)

        # 2. Compatibility Dimensions Assessment (8 dimensions)
        compatibility = self._assess_compatibility(fmt, quantum_status, canonical_alg)

        # 3. Evidence Items Classification
        evidence = [
            {
                "level": EvidenceLevel.OBSERVED,
                "type": "ALGORITHM_METADATA",
                "description": f"Extracted public key algorithm: {canonical_alg}",
            },
            {
                "level": EvidenceLevel.OBSERVED,
                "type": "FINGERPRINT",
                "description": f"SHA-256 Fingerprint: {target_record.get('sha256_fingerprint', 'N/A')}",
            },
            {
                "level": EvidenceLevel.INFERRED,
                "type": "QUANTUM_VULNERABILITY",
                "description": f"Quantum vulnerability status evaluated as {quantum_status}",
            },
            {
                "level": EvidenceLevel.UNKNOWN,
                "type": "VERIFICATION_LIBRARY",
                "description": "Production verification library support for post-quantum signatures is unverified.",
            },
        ]

        # 4. Readiness State & Migration Phase Mapping
        reasons = []
        blockers = []

        # Check for PQC compatibility evidence metadata (enables PARTIALLY_READY)
        has_pqc_testing = target_record.get("pqc_tested", False)
        has_pqc_compatibility = target_record.get("pqc_compatibility_verified", False)

        if quantum_status == "QUANTUM_RESISTANT":
            state = ReadinessState.PQC_READY
            phase = MigrationPhase.PHASE_4_VERIFICATION
            reasons.append(f"Artifact uses a post-quantum signature algorithm ({canonical_alg}).")
            reasons.append("No active quantum vulnerability detected.")
            recommended_next_step = "Perform continuous post-migration verification and monitoring."
        elif quantum_status == "HYBRID_READY":
            state = ReadinessState.HYBRID_READY
            phase = MigrationPhase.PHASE_3_HYBRID_OR_PQC_DEPLOYMENT
            reasons.append("Artifact uses dual classical + post-quantum hybrid signatures.")
            blockers.append("Full classical fallback deprecation required prior to pure PQC state.")
            recommended_next_step = "Validate hybrid signature verification performance across client endpoints."
        elif quantum_status in ("VULNERABLE", "WEAK_CLASSICAL") and (has_pqc_testing or has_pqc_compatibility):
            # PARTIALLY_READY: quantum-vulnerable but PQC migration work has begun
            state = ReadinessState.PARTIALLY_READY
            phase = MigrationPhase.PHASE_2_COMPATIBILITY_TESTING
            reasons.append(f"Current signature uses {canonical_alg}, which is quantum-vulnerable.")
            if has_pqc_testing:
                reasons.append("PQC compatibility testing has been initiated (pqc_tested=true).")
                evidence.append({
                    "level": EvidenceLevel.OBSERVED,
                    "type": "PQC_TESTING_EVIDENCE",
                    "description": "PQC testing metadata flag observed in artifact record.",
                })
            if has_pqc_compatibility:
                reasons.append("PQC compatibility has been partially verified (pqc_compatibility_verified=true).")
                evidence.append({
                    "level": EvidenceLevel.OBSERVED,
                    "type": "PQC_COMPATIBILITY_EVIDENCE",
                    "description": "PQC compatibility verification metadata flag observed in artifact record.",
                })
            blockers = [
                "Full PQC deployment has not been completed",
                "Production verification at scale not yet validated",
            ]
            cand_name = candidates[0]["name"] if candidates else "ML-DSA-65"
            recommended_next_step = f"Complete Phase 2 compatibility testing and proceed to hybrid/PQC deployment for {cand_name}."
        elif quantum_status in ("VULNERABLE", "WEAK_CLASSICAL"):
            state = ReadinessState.NOT_READY
            phase = MigrationPhase.PHASE_1_ASSESSMENT
            reasons.append(f"Current signature uses {canonical_alg}, which is vulnerable to Shor's algorithm on a CRQC.")
            reasons.append("No post-quantum or hybrid signature mechanism observed.")
            reasons.append("Production verifier and client compatibility have not been established.")

            blockers = [
                "Production verification library compatibility for PQC signature algorithms is unknown",
                "Downstream client ecosystem interoperability not verified",
                "PQC performance and signature size impact benchmark not completed",
            ]
            cand_name = candidates[0]["name"] if candidates else "ML-DSA-65"
            recommended_next_step = f"Initiate Phase 2 compatibility testing for candidate replacement {cand_name}."
        else:
            state = ReadinessState.UNKNOWN
            phase = MigrationPhase.PHASE_0_DISCOVERY
            reasons.append("Insufficient cryptographic metadata to establish PQC readiness.")
            blockers.append("Missing signature and key parameter details.")
            recommended_next_step = "Re-scan artifact with detailed metadata extraction enabled."

        # 5. Dependency Graph Integration
        downstream_count = 0
        if graph_engine is not None:
            # Query graph for node impact
            cert_fp = target_record.get("sha256_fingerprint")
            cert_node_id = f"cert:{cert_fp[:16]}" if cert_fp else None
            if cert_node_id and hasattr(graph_engine, "get_dependency_count"):
                downstream_count = graph_engine.get_dependency_count(cert_node_id)
                if downstream_count > 0:
                    reasons.append(f"Signing key has {downstream_count} downstream artifact dependencies in supply chain graph.")

        dep_impact = {
            "downstream_artifacts": downstream_count,
            "impact_level": "HIGH" if downstream_count >= 10 else ("MEDIUM" if downstream_count > 0 else "LOW"),
        }

        return {
            "assessment_id": f"pqc-eval-{hash(artifact_name) & 0xFFFFFFFF:08x}",
            "artifact_id": artifact_name,
            "current_cryptography": {
                "algorithm": canonical_alg,
                "family": algorithm_family,
                "key_size": target_record.get("key_size"),
                "curve": target_record.get("curve"),
                "quantum_status": quantum_status,
            },
            "readiness": {
                "state": state,
                "migration_phase": phase,
            },
            "candidate_algorithms": candidates,
            "compatibility": compatibility,
            "blockers": blockers,
            "evidence": evidence,
            "dependency_impact": dep_impact,
            "reasons": reasons,
            "recommended_next_step": recommended_next_step,
            "disclaimer": READINESS_DISCLAIMER,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _assess_compatibility(
        self,
        artifact_format: str,
        quantum_status: str,
        algorithm: str,
    ) -> Dict[str, str]:
        """
        Evaluates 8 compatibility dimensions for PQC migration readiness.

        Dimensions:
            cryptographic_support    — Can the PQC algorithm be used in this context?
            artifact_format          — Does the artifact format support PQC keys/signatures?
            certificate_support      — Does the certificate infrastructure support PQC?
            runtime_library_support  — Do production runtime libraries support PQC verification?
            verification_support     — Can downstream verifiers validate PQC signatures?
            deployment_support       — Is the deployment pipeline compatible with PQC?
            interoperability         — Do cross-ecosystem peers support PQC signatures?
            performance_impact       — Has performance impact of PQC been measured?
        """
        # Artifact format: X.509 is known to support PQC extensions (RFC drafts exist)
        fmt_u = (artifact_format or "").upper()
        if "X.509" in fmt_u:
            artifact_fmt = CompatibilityStatus.SUPPORTED
            certificate_sup = CompatibilityStatus.SUPPORTED
        else:
            artifact_fmt = CompatibilityStatus.PARTIAL
            certificate_sup = CompatibilityStatus.UNKNOWN

        # Cryptographic support: if quantum_resistant, PQC crypto is already present
        if quantum_status == "QUANTUM_RESISTANT":
            crypto_sup = CompatibilityStatus.SUPPORTED
        elif quantum_status == "HYBRID_READY":
            crypto_sup = CompatibilityStatus.PARTIAL
        else:
            crypto_sup = CompatibilityStatus.UNKNOWN

        return {
            "cryptographic_support": crypto_sup,
            "artifact_format": artifact_fmt,
            "certificate_support": certificate_sup,
            "runtime_library_support": CompatibilityStatus.UNKNOWN,
            "verification_support": CompatibilityStatus.UNKNOWN,
            "deployment_support": CompatibilityStatus.UNKNOWN,
            "interoperability": CompatibilityStatus.UNKNOWN,
            "performance_impact": CompatibilityStatus.UNKNOWN,
        }

    def _build_unknown_assessment(self, error_message: str) -> Dict[str, Any]:
        return {
            "assessment_id": "pqc-eval-unknown",
            "artifact_id": "unknown_artifact",
            "current_cryptography": {
                "algorithm": "UNKNOWN",
                "family": "UNKNOWN",
                "key_size": None,
                "curve": None,
                "quantum_status": "UNKNOWN",
            },
            "readiness": {
                "state": ReadinessState.UNKNOWN,
                "migration_phase": MigrationPhase.PHASE_0_DISCOVERY,
            },
            "candidate_algorithms": [],
            "compatibility": {
                "cryptographic_support": CompatibilityStatus.UNKNOWN,
                "artifact_format": CompatibilityStatus.UNKNOWN,
                "certificate_support": CompatibilityStatus.UNKNOWN,
                "runtime_library_support": CompatibilityStatus.UNKNOWN,
                "verification_support": CompatibilityStatus.UNKNOWN,
                "deployment_support": CompatibilityStatus.UNKNOWN,
                "interoperability": CompatibilityStatus.UNKNOWN,
                "performance_impact": CompatibilityStatus.UNKNOWN,
            },
            "blockers": [error_message],
            "evidence": [],
            "dependency_impact": {"downstream_artifacts": 0, "impact_level": "UNKNOWN"},
            "reasons": [error_message],
            "recommended_next_step": "Perform initial artifact scanning.",
            "disclaimer": READINESS_DISCLAIMER,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

