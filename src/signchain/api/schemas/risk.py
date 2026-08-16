"""
Pydantic schemas for Quantum Risk Assessments.
"""
from datetime import datetime
from typing import Any, Dict
from pydantic import BaseModel


class RiskResponse(BaseModel):
    """Schema representing an artifact quantum risk assessment."""
    id: str
    artifact_id: str
    risk_score: float
    risk_level: str
    factor_breakdown: Dict[str, Any]
    calculation_explanation: str
    model_version: str
    created_at: datetime

    model_config = {"from_attributes": True}
