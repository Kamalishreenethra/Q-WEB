"""
Migration Prioritization Assessments API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.dependencies import PaginationParams
from signchain.api.schemas.common import PaginatedResponse
from signchain.api.schemas.migration import MigrationResponse
from signchain.db.models import MigrationAssessment
from signchain.db.session import get_db

router = APIRouter(prefix="/migration", tags=["Migration Prioritization"])


@router.get("", response_model=PaginatedResponse[MigrationResponse])
def list_migration_assessments(
    priority: Optional[str] = Query(None, alias="priority", description="Filter by priority code (P1, P2, P3, P4)"),
    priority_level: Optional[str] = Query(None, description="Filter by priority tier (CRITICAL, HIGH, MEDIUM, LOW)"),
    migration_status: Optional[str] = Query(None, description="Filter by migration status (ACTION_REQUIRED, READY, etc.)"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
):
    """Lists migration prioritization assessments with priority and status filters."""
    query = db.query(MigrationAssessment)

    if priority:
        query = query.filter(MigrationAssessment.priority_code == priority)
    if priority_level:
        query = query.filter(MigrationAssessment.priority_level == priority_level)
    if migration_status:
        query = query.filter(MigrationAssessment.migration_status == migration_status)

    total = query.count()
    items = query.order_by(MigrationAssessment.priority_score.desc()).offset(pagination.offset).limit(pagination.page_size).all()
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/{artifact_id}", response_model=MigrationResponse)
def get_migration_by_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves migration priority, score, recommendations, and rationale for an artifact."""
    mig = db.query(MigrationAssessment).filter(MigrationAssessment.artifact_id == artifact_id).first()
    if not mig:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Migration assessment for artifact ID '{artifact_id}' not found.",
        )
    return mig
