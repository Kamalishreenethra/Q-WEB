"""
Scan Ingestion Service for SignChain.
Safely ingests scanner results and pipeline intelligence into normalized database models.
Reuses existing domain engines (Classifier, Risk, Graph, Readiness, Migration) as sources of truth.
"""
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from signchain.db.models import (
    Scan,
    Artifact,
    Certificate,
    Signature,
    RiskAssessment,
    PQCReadinessAssessment,
    MigrationAssessment,
    DependencyNode,
    DependencyEdge,
)
from signchain.graph.dependency_graph import DependencyGraph, NodeType
from signchain.risk.risk_engine import QuantumRiskEngine
from signchain.pqc.readiness_engine import PQCReadinessEngine
from signchain.migration.migration_engine import MigrationPrioritizationEngine


class IngestionService:
    """
    Service for validating and persisting scanner outputs into the database.
    """

    def __init__(self, db: Session):
        self.db = db
        self.risk_engine = QuantumRiskEngine()
        self.pqc_engine = PQCReadinessEngine()
        self.migration_engine = MigrationPrioritizationEngine()

    def ingest_scan_result(self, raw_result: Dict[str, Any], scanner_version: str = "0.1.0") -> Scan:
        """
        Ingests a single raw scan result dictionary from any SignChain scanner plugin.
        """
        if not isinstance(raw_result, dict):
            raise ValueError("Scan result must be a JSON dictionary.")

        status = raw_result.get("status", "SUCCESS")
        is_error = status == "ERROR"
        file_path = raw_result.get("file_path", "unknown_path")
        artifact_name = raw_result.get("artifact_name") or raw_result.get("name") or "unknown_artifact"
        duration = float(raw_result.get("scan_time_sec", 0.0))

        # 1. Create Scan Record
        scan_id = str(uuid.uuid4())
        scan = Scan(
            id=scan_id,
            scanner_version=scanner_version,
            status=status,
            duration_sec=duration,
            artifact_count=0 if is_error else 1,
            error_count=1 if is_error else 0,
            metadata_json={"ecosystem": raw_result.get("ecosystem", "UNKNOWN")},
        )
        self.db.add(scan)

        if is_error:
            self.db.commit()
            self.db.refresh(scan)
            return scan

        # 2. Build Dependency Graph
        graph = DependencyGraph()
        graph.build_from_scan_result(raw_result, artifact_id=artifact_name)

        # 3. Determine Ecosystem and Artifact Type
        ecosystem = raw_result.get("ecosystem", "X509")
        artifact_type = "UNKNOWN"
        art_meta = raw_result.get("artifact")

        if ecosystem == "CONTAINER" or (isinstance(art_meta, dict) and art_meta.get("type") == "OCI_IMAGE"):
            artifact_type = "OCI_IMAGE"
            ecosystem = "CONTAINER"
        elif ecosystem == "SIGSTORE" or raw_result.get("media_type") == "application/vnd.dev.sigstore.bundle+json;version=0.3":
            artifact_type = "SIGSTORE_BUNDLE"
            ecosystem = "SIGSTORE"
        elif ecosystem == "OPENPGP" or "OpenPGP" in str(raw_result.get("format", "")):
            artifact_type = "PGP_OBJECT"
            ecosystem = "OPENPGP"
        elif ecosystem == "AUTHENTICODE" or "PE" in str(raw_result.get("format", "")):
            artifact_type = "PE_BINARY"
            ecosystem = "AUTHENTICODE"
        else:
            artifact_type = "X509_CERTIFICATE"
            ecosystem = "X509"

        # 4. Create Artifact Record
        registry = art_meta.get("registry") if isinstance(art_meta, dict) else None
        repository = art_meta.get("repository") if isinstance(art_meta, dict) else None
        tag = art_meta.get("tag") if isinstance(art_meta, dict) else None
        digest = art_meta.get("digest") if isinstance(art_meta, dict) else raw_result.get("digest")

        artifact = Artifact(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            name=artifact_name,
            path=file_path,
            artifact_type=artifact_type,
            ecosystem=ecosystem,
            registry=registry,
            repository=repository,
            tag=tag,
            digest=digest,
        )
        self.db.add(artifact)

        # 5. Persist Certificates & Signatures
        certs_list = raw_result.get("certificates", [])
        if not certs_list and raw_result.get("certificate"):
            certs_list = [raw_result.get("certificate")]

        for cert_dict in certs_list:
            fp = cert_dict.get("sha256_fingerprint") or cert_dict.get("fingerprint")
            if not fp:
                continue

            existing_cert = self.db.query(Certificate).filter(Certificate.fingerprint == fp).first()
            if not existing_cert:
                cert = Certificate(
                    fingerprint=fp,
                    subject=cert_dict.get("subject", "Unknown Subject"),
                    issuer=cert_dict.get("issuer", "Unknown Issuer"),
                    serial_number=str(cert_dict.get("serial_number", "")),
                    algorithm=cert_dict.get("canonical_algorithm", "UNKNOWN"),
                    key_size=cert_dict.get("key_size_bits"),
                    curve=cert_dict.get("curve"),
                    valid_from=cert_dict.get("not_valid_before"),
                    valid_to=cert_dict.get("not_valid_after"),
                    quantum_status=cert_dict.get("quantum_status", "UNKNOWN"),
                    is_ca=cert_dict.get("is_ca", False),
                )
                self.db.add(cert)

            # Add Signature
            sig_dict = raw_result.get("signature", {})
            sig = Signature(
                id=str(uuid.uuid4()),
                artifact_id=artifact.id,
                certificate_fingerprint=fp,
                ecosystem=ecosystem,
                signature_type=sig_dict.get("signature_type", "DIGITAL_SIGNATURE"),
                status=sig_dict.get("status", "SIGNATURE_PRESENT"),
                verification_status=sig_dict.get("verification", "VERIFICATION_NOT_PERFORMED"),
                algorithm=cert_dict.get("canonical_algorithm", "UNKNOWN"),
                signing_time=None,
                evidence_status="OBSERVED",
            )
            self.db.add(sig)

        # If no certificate, create an unsigned signature record if appropriate
        if not certs_list:
            sig_dict = raw_result.get("signature", {})
            sig = Signature(
                id=str(uuid.uuid4()),
                artifact_id=artifact.id,
                certificate_fingerprint=None,
                ecosystem=ecosystem,
                signature_type=sig_dict.get("signature_type", "NONE"),
                status=sig_dict.get("status", "UNSIGNED"),
                verification_status=sig_dict.get("verification", "VERIFICATION_NOT_PERFORMED"),
                algorithm=raw_result.get("canonical_algorithm", "NONE"),
                signing_time=None,
                evidence_status="MISSING",
            )
            self.db.add(sig)

        # 6. Evaluate & Persist Risk Assessment
        risk_score = float(raw_result.get("risk_score", 0.0))
        risk_level = raw_result.get("risk_level", "LOW")
        breakdown = raw_result.get("factor_breakdown", {})
        explanation = raw_result.get("calculation_explanation", f"Calculated risk score: {risk_score}")

        risk_rec = RiskAssessment(
            id=str(uuid.uuid4()),
            artifact_id=artifact.id,
            risk_score=risk_score,
            risk_level=risk_level,
            factor_breakdown=breakdown,
            calculation_explanation=explanation,
            model_version="1.0.0",
        )
        self.db.add(risk_rec)

        # 7. Evaluate & Persist PQC Readiness Assessment
        pqc_eval = self.pqc_engine.evaluate_readiness(raw_result, graph_engine=graph)
        readiness_info = pqc_eval.get("readiness", {})

        pqc_rec = PQCReadinessAssessment(
            id=str(uuid.uuid4()),
            artifact_id=artifact.id,
            readiness_state=readiness_info.get("state", "UNKNOWN"),
            migration_phase=readiness_info.get("migration_phase", "PHASE_0_INVENTORY"),
            candidate_algorithms=readiness_info.get("candidate_algorithms", []),
            compatibility=readiness_info.get("compatibility", {}),
            blockers=readiness_info.get("blockers", []),
            evidence=pqc_eval.get("evidence", {}),
            assessment_version="1.0.0",
        )
        self.db.add(pqc_rec)

        # 8. Evaluate & Persist Migration Prioritization Assessment
        if certs_list:
            mig_plan = self.migration_engine.prioritize_all(certs_list, graph_engine=graph)
            targets = mig_plan.get("targets", [])
            primary_target = targets[0] if targets else {}

            mig_rec = MigrationAssessment(
                id=str(uuid.uuid4()),
                artifact_id=artifact.id,
                priority_code=primary_target.get("priority_code", "P3"),
                priority_score=float(primary_target.get("priority_score", 50.0)),
                priority_level=primary_target.get("priority_level", "MEDIUM"),
                migration_status="ACTION_REQUIRED",
                recommended_action=primary_target.get("recommended_action", "Plan cryptographic migration."),
                blockers=primary_target.get("blockers", []),
                rationale=primary_target.get("rationale", "Standard migration priority."),
                migration_phase="PHASE_1_DISCOVERY",
            )
            self.db.add(mig_rec)
        else:
            mig_rec = MigrationAssessment(
                id=str(uuid.uuid4()),
                artifact_id=artifact.id,
                priority_code="P4",
                priority_score=0.0,
                priority_level="LOW",
                migration_status="READY",
                recommended_action="No active vulnerable signatures detected.",
                blockers=[],
                rationale="Unsigned or low risk artifact.",
                migration_phase="NONE",
            )
            self.db.add(mig_rec)

        # 9. Persist Dependency Graph Nodes & Edges
        for node_id, data in graph.graph.nodes(data=True):
            node_type_val = data.get("type", NodeType.ARTIFACT)
            if hasattr(node_type_val, "value"):
                node_type_val = node_type_val.value
            node_rec = DependencyNode(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                node_id=str(node_id),
                node_type=str(node_type_val),
                name=str(data.get("name", node_id)),
                metadata_json=data.get("metadata", {}),
            )
            self.db.add(node_rec)

        for u, v, data in graph.graph.edges(data=True):
            edge_type_val = data.get("type", "DEPENDS_ON")
            if hasattr(edge_type_val, "value"):
                edge_type_val = edge_type_val.value
            edge_rec = DependencyEdge(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                source_id=str(u),
                target_id=str(v),
                edge_type=str(edge_type_val),
                metadata_json=data.get("metadata", {}),
            )
            self.db.add(edge_rec)

        self.db.commit()
        self.db.refresh(scan)
        return scan
