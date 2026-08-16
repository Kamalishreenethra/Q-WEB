"""
Pydantic schemas for PQC Readiness Assessments.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class PQCReadinessResponse(BaseModel):
    """Schema representing an artifact PQC readiness assessment."""
    id: str
    artifact_id: str
    readiness_state: str
    migration_phase: str
    candidate_algorithms: Optional[List[Any]] = None
    compatibility: Optional[Dict[str, Any]] = None
    blockers: Optional[List[Any]] = None
    evidence: Optional[Any] = None
    assessment_version: str

    model_config = {"from_attributes": True}
