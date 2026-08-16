"""
Scan history and scan ingestion API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.dependencies import PaginationParams
from signchain.api.schemas.common import PaginatedResponse
from signchain.api.schemas.scan import ScanResponse, ScanIngestionRequest
from signchain.api.services.ingestion_service import IngestionService
from signchain.db.models import Scan
from signchain.db.session import get_db

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("", response_model=PaginatedResponse[ScanResponse])
def list_scans(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter scans by execution status"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
):
    """Lists historical scan runs with optional status filtering and pagination."""
    query = db.query(Scan)
    if status_filter:
        query = query.filter(Scan.status == status_filter)

    total = query.count()
    items = query.order_by(Scan.timestamp.desc()).offset(pagination.offset).limit(pagination.page_size).all()
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves metadata and execution metrics for a specific scan ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )
    return scan


@router.post("/ingest", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def ingest_scan(
    payload: ScanIngestionRequest,
    db: Session = Depends(get_db),
):
    """Ingests a raw scan result dictionary into the database."""
    service = IngestionService(db)
    try:
        scan = service.ingest_scan_result(
            raw_result=payload.raw_result,
            scanner_version=payload.scanner_version or "0.1.0",
        )
        return scan
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to ingest scan result: {str(e)}",
        )
