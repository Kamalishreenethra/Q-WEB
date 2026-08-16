"""
Artifacts API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.dependencies import PaginationParams
from signchain.api.schemas.common import PaginatedResponse
from signchain.api.schemas.artifact import ArtifactResponse, ArtifactDetailResponse
from signchain.db.models import Artifact
from signchain.db.session import get_db

router = APIRouter(prefix="/artifacts", tags=["Artifacts"])


@router.get("", response_model=PaginatedResponse[ArtifactResponse])
def list_artifacts(
    ecosystem: Optional[str] = Query(None, description="Filter by ecosystem (e.g. X509, AUTHENTICODE, OPENPGP, SIGSTORE, CONTAINER)"),
    artifact_type: Optional[str] = Query(None, description="Filter by artifact type (e.g. OCI_IMAGE, PE_BINARY, PGP_OBJECT)"),
    scan_id: Optional[str] = Query(None, description="Filter by scan execution ID"),
    name: Optional[str] = Query(None, description="Filter by artifact name substring"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
):
    """Lists discovered artifacts with ecosystem, type, and name filters."""
    query = db.query(Artifact)

    if ecosystem:
        query = query.filter(Artifact.ecosystem == ecosystem)
    if artifact_type:
        query = query.filter(Artifact.artifact_type == artifact_type)
    if scan_id:
        query = query.filter(Artifact.scan_id == scan_id)
    if name:
        query = query.filter(Artifact.name.contains(name))

    total = query.count()
    items = query.order_by(Artifact.created_at.desc()).offset(pagination.offset).limit(pagination.page_size).all()
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/{artifact_id}", response_model=ArtifactDetailResponse)
def get_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves full details, signatures, and engine evaluations for a specific artifact ID."""
    artifact = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact with ID '{artifact_id}' not found.",
        )
    return artifact
