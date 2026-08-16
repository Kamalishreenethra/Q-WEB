"""
Unit tests for SignChain FastAPI REST API endpoints, pagination, filtering, and CLI commands.
"""
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from typer.testing import CliRunner

from signchain.api.app import app
from signchain.db.base import Base
from signchain.db.session import get_db
from signchain.api.services.ingestion_service import IngestionService
from signchain.scanners.x509_scanner import X509Scanner
from signchain.scanners.container_scanner import ContainerScanner
from signchain.cli.main import app as cli_app
from tests.fixtures.certs import generate_rsa_certificate
from tests.fixtures.container import generate_cosign_signed_oci_manifest

runner = CliRunner()


@pytest.fixture(scope="function")
def api_client():
    """Provides a TestClient with an isolated shared in-memory SQLite database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client, TestingSessionLocal()

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_health_endpoint(api_client):
    client, _ = api_client
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["version"] == "0.1.0"


def test_ingest_and_get_scan(api_client, tmp_path: Path):
    client, db = api_client
    cert_pem, _ = generate_rsa_certificate(key_size=2048)
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)

    scanner = X509Scanner()
    raw_res = scanner.scan(str(cert_file))

    # POST /scans/ingest
    resp = client.post("/scans/ingest", json={"raw_result": raw_res})
    assert resp.status_code == 201
    scan_data = resp.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "SUCCESS"

    # GET /scans/{scan_id}
    get_resp = client.get(f"/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == scan_id


def test_artifacts_and_filtering(api_client, tmp_path: Path):
    client, db = api_client
    service = IngestionService(db)

    # Ingest X509
    cert_pem, _ = generate_rsa_certificate(key_size=2048)
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)
    raw_x509 = X509Scanner().scan(str(cert_file))
    service.ingest_scan_result(raw_x509)

    # Ingest Container
    manifest = generate_cosign_signed_oci_manifest()
    manifest_file = tmp_path / "app.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    raw_oci = ContainerScanner().scan(str(manifest_file))
    service.ingest_scan_result(raw_oci)

    # List all artifacts
    resp = client.get("/artifacts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2

    # Filter by ecosystem
    oci_resp = client.get("/artifacts?ecosystem=CONTAINER")
    assert oci_resp.status_code == 200
    oci_data = oci_resp.json()
    assert oci_data["total"] == 1
    assert oci_data["items"][0]["ecosystem"] == "CONTAINER"

    # Get single artifact detail
    art_id = oci_data["items"][0]["id"]
    detail_resp = client.get(f"/artifacts/{art_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["risk_assessment"] is not None
    assert detail["pqc_assessment"] is not None
    assert detail["migration_assessment"] is not None


def test_certificates_and_risk_endpoints(api_client, tmp_path: Path):
    client, db = api_client
    cert_pem, _ = generate_rsa_certificate(key_size=2048)
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)
    raw_x509 = X509Scanner().scan(str(cert_file))
    IngestionService(db).ingest_scan_result(raw_x509)

    # List certificates
    cert_resp = client.get("/certificates")
    assert cert_resp.status_code == 200
    certs = cert_resp.json()
    assert certs["total"] >= 1
    fp = certs["items"][0]["fingerprint"]

    # Get certificate by fingerprint
    fp_resp = client.get(f"/certificates/{fp}")
    assert fp_resp.status_code == 200
    assert fp_resp.json()["fingerprint"] == fp

    # List Risk
    risk_resp = client.get("/risk")
    assert risk_resp.status_code == 200
    assert risk_resp.json()["total"] >= 1


def test_pqc_migration_and_graph_endpoints(api_client, tmp_path: Path):
    client, db = api_client
    manifest = generate_cosign_signed_oci_manifest()
    manifest_file = tmp_path / "app.oci.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    raw_oci = ContainerScanner().scan(str(manifest_file))
    IngestionService(db).ingest_scan_result(raw_oci)

    # Get artifact
    arts = client.get("/artifacts").json()
    art_id = arts["items"][0]["id"]

    # GET /pqc/{artifact_id}
    pqc_resp = client.get(f"/pqc/{art_id}")
    assert pqc_resp.status_code == 200
    assert pqc_resp.json()["readiness_state"] == "NOT_READY"

    # GET /migration/{artifact_id}
    mig_resp = client.get(f"/migration/{art_id}")
    assert mig_resp.status_code == 200
    assert mig_resp.json()["priority_code"] in ("P1", "P2", "P3")

    # GET /graph/{artifact_id}
    graph_resp = client.get(f"/graph/{art_id}")
    assert graph_resp.status_code == 200
    assert graph_resp.json()["statistics"]["node_count"] >= 3


def test_not_found_handling(api_client):
    client, _ = api_client
    assert client.get("/artifacts/non_existent_id").status_code == 404
    assert client.get("/certificates/non_existent_fp").status_code == 404
    assert client.get("/risk/non_existent_id").status_code == 404
    assert client.get("/pqc/non_existent_id").status_code == 404
    assert client.get("/migration/non_existent_id").status_code == 404
    assert client.get("/graph/non_existent_id").status_code == 404


def test_cli_store_and_serve_help(tmp_path: Path):
    cert_pem, _ = generate_rsa_certificate(key_size=2048)
    cert_file = tmp_path / "cli_cert.pem"
    cert_file.write_bytes(cert_pem)

    # Test CLI store command
    res = runner.invoke(cli_app, ["store", str(cert_file)])
    assert res.exit_code == 0
    assert "Successfully stored scan record" in res.stdout

    # Test CLI serve --help command
    help_res = runner.invoke(cli_app, ["serve", "--help"])
    assert help_res.exit_code == 0
    assert "Start the SignChain FastAPI REST API backend server" in help_res.stdout
