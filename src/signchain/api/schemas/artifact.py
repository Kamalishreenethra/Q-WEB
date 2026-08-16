"""
Pydantic schemas for Artifacts and Signatures.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from signchain.api.schemas.certificate import CertificateResponse
from signchain.api.schemas.risk import RiskResponse
from signchain.api.schemas.pqc import PQCReadinessResponse
from signchain.api.schemas.migration import MigrationResponse


class SignatureResponse(BaseModel):
    """Schema representing an individual digital signature."""
    id: str
    artifact_id: str
    certificate_fingerprint: Optional[str] = None
    ecosystem: str
    signature_type: str
    status: str
    verification_status: str
    algorithm: str
    signing_time: Optional[str] = None
    evidence_status: str
    certificate: Optional[CertificateResponse] = None

    model_config = {"from_attributes": True}


class ArtifactResponse(BaseModel):
    """Schema representing an individual software artifact."""
    id: str
    scan_id: str
    name: str
    path: str
    artifact_type: str
    ecosystem: str
    registry: Optional[str] = None
    repository: Optional[str] = None
    tag: Optional[str] = None
    digest: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ArtifactDetailResponse(ArtifactResponse):
    """Detailed artifact schema including signatures and engine assessment summaries."""
    signatures: List[SignatureResponse] = []
    risk_assessment: Optional[RiskResponse] = None
    pqc_assessment: Optional[PQCReadinessResponse] = None
    migration_assessment: Optional[MigrationResponse] = None
