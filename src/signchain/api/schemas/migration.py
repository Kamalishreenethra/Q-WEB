"""
Pydantic schemas for Migration Prioritization Assessments.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class MigrationResponse(BaseModel):
    """Schema representing an artifact migration prioritization assessment."""
    id: str
    artifact_id: str
    priority_code: str
    priority_score: float
    priority_level: str
    migration_status: str
    recommended_action: str
    blockers: Optional[List[Any]] = None
    rationale: str
    migration_phase: str

    model_config = {"from_attributes": True}
