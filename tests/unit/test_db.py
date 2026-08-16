"""
Unit tests for SignChain database models, SQLAlchemy persistence, and IngestionService.
"""
import uuid
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from signchain.db.base import Base
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
from signchain.api.services.ingestion_service import IngestionService
from signchain.scanners.x509_scanner import X509Scanner
from signchain.scanners.container_scanner import ContainerScanner
from tests.fixtures.certs import generate_rsa_certificate
from tests.fixtures.container import generate_cosign_signed_oci_manifest
import json


@pytest.fixture
def test_db():
    """Provides a fresh isolated SQLite in-memory database session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def test_db_model_creation(test_db):
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        scanner_version="0.1.0",
        status="SUCCESS",
        duration_sec=0.015,
        artifact_count=1,
        error_count=0,
    )
    test_db.add(scan)
    test_db.commit()

    retrieved = test_db.query(Scan).filter(Scan.id == scan_id).first()
    assert retrieved is not None
    assert retrieved.status == "SUCCESS"
    assert retrieved.duration_sec == 0.015


def test_artifact_and_certificate_persistence(test_db):
    scan = Scan(id=str(uuid.uuid4()), status="SUCCESS", duration_sec=0.1)
    test_db.add(scan)

    art = Artifact(
        id=str(uuid.uuid4()),
        scan_id=scan.id,
        name="test_app.exe",
        path="/path/to/test_app.exe",
        artifact_type="PE_BINARY",
        ecosystem="AUTHENTICODE",
    )
    test_db.add(art)

    cert = Certificate(
        fingerprint="a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef",
        subject="CN=SignChain Test",
        issuer="CN=SignChain CA",
        algorithm="RSA-2048",
        quantum_status="VULNERABLE",
        is_ca=False,
    )
    test_db.add(cert)

    sig = Signature(
        id=str(uuid.uuid4()),
        artifact_id=art.id,
        certificate_fingerprint=cert.fingerprint,
        ecosystem="AUTHENTICODE",
        signature_type="AUTHENTICODE_PKCS7",
        status="SIGNATURE_PRESENT",
        verification_status="VERIFICATION_NOT_PERFORMED",
        algorithm="RSA-2048",
    )
    test_db.add(sig)

    risk = RiskAssessment(
        id=str(uuid.uuid4()),
        artifact_id=art.id,
        risk_score=78.5,
        risk_level="HIGH",
        factor_breakdown={"crypto": 80.0},
        calculation_explanation="Test risk calculation",
        model_version="1.0.0",
    )
    test_db.add(risk)

    test_db.commit()

    # Query back
    saved_art = test_db.query(Artifact).filter(Artifact.id == art.id).first()
    assert saved_art is not None
    assert len(saved_art.signatures) == 1
    assert saved_art.signatures[0].certificate.algorithm == "RSA-2048"
    assert saved_art.risk_assessment.risk_score == 78.5


def test_ingestion_service_x509(test_db, tmp_path: Path):
    cert_pem, _ = generate_rsa_certificate(key_size=2048)
    cert_file = tmp_path / "test_cert.pem"
    cert_file.write_bytes(cert_pem)

    scanner = X509Scanner()
    raw_res = scanner.scan(str(cert_file))
    assert raw_res["status"] == "SUCCESS"

    service = IngestionService(test_db)
    scan = service.ingest_scan_result(raw_res)

    assert scan.status == "SUCCESS"
    assert scan.artifact_count == 1
    assert len(scan.artifacts) == 1

    art = scan.artifacts[0]
    assert art.ecosystem == "X509"
    assert art.risk_assessment is not None
    assert art.pqc_assessment is not None
    assert art.migration_assessment is not None


def test_ingestion_service_container(test_db, tmp_path: Path):
    manifest = generate_cosign_signed_oci_manifest()
    manifest_file = tmp_path / "app.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    scanner = ContainerScanner()
    raw_res = scanner.scan(str(manifest_file))
    assert raw_res["status"] == "SUCCESS"

    service = IngestionService(test_db)
    scan = service.ingest_scan_result(raw_res)

    assert scan.status == "SUCCESS"
    art = scan.artifacts[0]
    assert art.ecosystem == "CONTAINER"
    assert art.artifact_type == "OCI_IMAGE"
    assert len(scan.nodes) >= 3
    assert len(scan.edges) >= 2
