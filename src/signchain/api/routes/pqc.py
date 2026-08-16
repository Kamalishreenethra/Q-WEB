"""
PQC Readiness Assessments API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.dependencies import PaginationParams
from signchain.api.schemas.common import PaginatedResponse
from signchain.api.schemas.pqc import PQCReadinessResponse
from signchain.db.models import PQCReadinessAssessment
from signchain.db.session import get_db

router = APIRouter(prefix="/pqc", tags=["PQC Readiness"])


@router.get("", response_model=PaginatedResponse[PQCReadinessResponse])
def list_pqc_assessments(
    readiness_state: Optional[str] = Query(None, description="Filter by readiness state (NOT_READY, PARTIALLY_READY, HYBRID_READY, PQC_READY)"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
):
    """Lists PQC readiness assessments with optional state filter."""
    query = db.query(PQCReadinessAssessment)
    if readiness_state:
        query = query.filter(PQCReadinessAssessment.readiness_state == readiness_state)

    total = query.count()
    items = query.order_by(PQCReadinessAssessment.assessment_version.asc()).offset(pagination.offset).limit(pagination.page_size).all()
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/{artifact_id}", response_model=PQCReadinessResponse)
def get_pqc_by_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves PQC readiness assessment, candidate algorithms, and blockers for an artifact."""
    pqc = db.query(PQCReadinessAssessment).filter(PQCReadinessAssessment.artifact_id == artifact_id).first()
    if not pqc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PQC readiness assessment for artifact ID '{artifact_id}' not found.",
        )
    return pqc
