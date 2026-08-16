"""
Quantum Risk Assessments API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.dependencies import PaginationParams
from signchain.api.schemas.common import PaginatedResponse
from signchain.api.schemas.risk import RiskResponse
from signchain.db.models import RiskAssessment
from signchain.db.session import get_db

router = APIRouter(prefix="/risk", tags=["Quantum Risk"])


@router.get("", response_model=PaginatedResponse[RiskResponse])
def list_risk_assessments(
    risk_level: Optional[str] = Query(None, description="Filter by risk tier (LOW, MEDIUM, HIGH, CRITICAL)"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
):
    """Lists quantum risk assessments with optional risk level filter."""
    query = db.query(RiskAssessment)
    if risk_level:
        query = query.filter(RiskAssessment.risk_level == risk_level)

    total = query.count()
    items = query.order_by(RiskAssessment.risk_score.desc()).offset(pagination.offset).limit(pagination.page_size).all()
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/{artifact_id}", response_model=RiskResponse)
def get_risk_by_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves quantum risk assessment and factor breakdown for an artifact."""
    risk = db.query(RiskAssessment).filter(RiskAssessment.artifact_id == artifact_id).first()
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment for artifact ID '{artifact_id}' not found.",
        )
    return risk
