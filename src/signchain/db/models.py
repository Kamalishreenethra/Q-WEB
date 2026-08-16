"""
SQLAlchemy Normalized Database Models for SignChain.
Stores scan history, discovered artifacts, signatures, certificates,
and outputs from the Risk, Graph, PQC Readiness, and Migration engines.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from signchain.db.base import Base


def generate_uuid() -> str:
    """Generates a random UUID4 string."""
    return str(uuid.uuid4())


def get_utc_now() -> datetime:
    """Returns current UTC datetime."""
    return datetime.now(timezone.utc)


class Scan(Base):
    """Represents a discrete discovery scan execution over software supply chain artifacts."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    scanner_version = Column(String(32), default="0.1.0", nullable=False)
    status = Column(String(32), default="SUCCESS", nullable=False, index=True)
    duration_sec = Column(Float, default=0.0, nullable=False)
    artifact_count = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)
    metadata_json = Column(JSON, default=dict)

    # Relationships
    artifacts = relationship("Artifact", back_populates="scan", cascade="all, delete-orphan")
    nodes = relationship("DependencyNode", back_populates="scan", cascade="all, delete-orphan")
    edges = relationship("DependencyEdge", back_populates="scan", cascade="all, delete-orphan")


class Artifact(Base):
    """Represents an individual discovered software artifact (binary, certificate, package, image, etc.)."""
    __tablename__ = "artifacts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    path = Column(Text, nullable=False)
    artifact_type = Column(String(64), nullable=False, index=True)  # X509_CERTIFICATE, PE_BINARY, PGP_OBJECT, SIGSTORE_BUNDLE, OCI_IMAGE
    ecosystem = Column(String(64), nullable=False, index=True)      # X509, AUTHENTICODE, OPENPGP, SIGSTORE, CONTAINER
    registry = Column(String(255), nullable=True)
    repository = Column(String(255), nullable=True)
    tag = Column(String(128), nullable=True)
    digest = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="artifacts")
    signatures = relationship("Signature", back_populates="artifact", cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="artifact", uselist=False, cascade="all, delete-orphan")
    pqc_assessment = relationship("PQCReadinessAssessment", back_populates="artifact", uselist=False, cascade="all, delete-orphan")
    migration_assessment = relationship("MigrationAssessment", back_populates="artifact", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_artifacts_ecosystem_type", "ecosystem", "artifact_type"),
    )


class Certificate(Base):
    """Represents reusable cryptographic certificate metadata (leaf, intermediate, or root CA)."""
    __tablename__ = "certificates"

    fingerprint = Column(String(64), primary_key=True)  # SHA-256 or SHA-1 hex fingerprint
    subject = Column(Text, nullable=False)
    issuer = Column(Text, nullable=False)
    serial_number = Column(String(128), nullable=True)
    algorithm = Column(String(64), nullable=False, index=True)  # Canonical name e.g. RSA-2048, ECDSA-secp256r1, ML-DSA-44
    key_size = Column(Integer, nullable=True)
    curve = Column(String(64), nullable=True)
    valid_from = Column(String(64), nullable=True)
    valid_to = Column(String(64), nullable=True)
    quantum_status = Column(String(32), nullable=False, index=True)  # VULNERABLE, QUANTUM_RESISTANT, WEAK_CLASSICAL, UNKNOWN
    is_ca = Column(Boolean, default=False, nullable=False)

    # Relationships
    signatures = relationship("Signature", back_populates="certificate")


class Signature(Base):
    """Represents a digital signature binding an artifact to a signing key or certificate."""
    __tablename__ = "signatures"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    certificate_fingerprint = Column(String(64), ForeignKey("certificates.fingerprint"), nullable=True, index=True)
    ecosystem = Column(String(64), nullable=False, index=True)
    signature_type = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, index=True)              # SIGNATURE_PRESENT, UNSIGNED, SIGNATURE_MISSING
    verification_status = Column(String(64), nullable=False, index=True) # VERIFICATION_NOT_PERFORMED, SIGNATURE_VERIFIED, VERIFICATION_FAILED
    algorithm = Column(String(64), nullable=False)
    signing_time = Column(String(64), nullable=True)
    evidence_status = Column(String(32), default="OBSERVED", nullable=False)

    # Relationships
    artifact = relationship("Artifact", back_populates="signatures")
    certificate = relationship("Certificate", back_populates="signatures")


class RiskAssessment(Base):
    """Persisted output from the Phase 4 Quantum Risk Engine for an artifact."""
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    risk_score = Column(Float, nullable=False, index=True)
    risk_level = Column(String(32), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    factor_breakdown = Column(JSON, nullable=False)              # w_c * R_crypto, w_a * C_asset, etc.
    calculation_explanation = Column(Text, nullable=False)
    model_version = Column(String(32), default="1.0.0", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Relationships
    artifact = relationship("Artifact", back_populates="risk_assessment")


class PQCReadinessAssessment(Base):
    """Persisted output from the Phase 6 PQC Readiness Engine for an artifact."""
    __tablename__ = "pqc_readiness_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    readiness_state = Column(String(32), nullable=False, index=True)  # NOT_READY, PARTIALLY_READY, HYBRID_READY, PQC_READY, UNKNOWN
    migration_phase = Column(String(64), nullable=False)
    candidate_algorithms = Column(JSON, default=list)
    compatibility = Column(JSON, default=dict)
    blockers = Column(JSON, default=list)
    evidence = Column(JSON, default=dict)
    assessment_version = Column(String(32), default="1.0.0", nullable=False)

    # Relationships
    artifact = relationship("Artifact", back_populates="pqc_assessment")


class MigrationAssessment(Base):
    """Persisted output from the Phase 7 Migration Prioritization Engine for an artifact."""
    __tablename__ = "migration_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    priority_code = Column(String(8), nullable=False, index=True)   # P1, P2, P3, P4
    priority_score = Column(Float, nullable=False, index=True)
    priority_level = Column(String(32), nullable=False, index=True) # CRITICAL, HIGH, MEDIUM, LOW
    migration_status = Column(String(32), default="ACTION_REQUIRED", nullable=False, index=True)
    recommended_action = Column(Text, nullable=False)
    blockers = Column(JSON, default=list)
    rationale = Column(Text, nullable=False)
    migration_phase = Column(String(64), nullable=False)

    # Relationships
    artifact = relationship("Artifact", back_populates="migration_assessment")


class DependencyNode(Base):
    """Persisted representation of a node in the NetworkX dependency graph."""
    __tablename__ = "dependency_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    node_id = Column(String(255), nullable=False, index=True)
    node_type = Column(String(64), nullable=False, index=True)  # ARTIFACT, CERTIFICATE, SIGNER, CA, CONTAINER, PGP_KEY
    name = Column(String(255), nullable=False)
    metadata_json = Column(JSON, default=dict)

    # Relationships
    scan = relationship("Scan", back_populates="nodes")


class DependencyEdge(Base):
    """Persisted representation of a directed edge in the NetworkX dependency graph."""
    __tablename__ = "dependency_edges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id = Column(String(255), nullable=False, index=True)
    target_id = Column(String(255), nullable=False, index=True)
    edge_type = Column(String(64), nullable=False, index=True)  # SIGNED_BY, ISSUED_BY, DEPENDS_ON, CONTAINS, RECORDED_IN, BELONGS_TO
    metadata_json = Column(JSON, default=dict)

    # Relationships
    scan = relationship("Scan", back_populates="edges")
