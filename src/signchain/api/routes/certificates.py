"""
Certificates and cryptographic keys API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.dependencies import PaginationParams
from signchain.api.schemas.common import PaginatedResponse
from signchain.api.schemas.certificate import CertificateResponse
from signchain.db.models import Certificate
from signchain.db.session import get_db

router = APIRouter(prefix="/certificates", tags=["Certificates"])


@router.get("", response_model=PaginatedResponse[CertificateResponse])
def list_certificates(
    algorithm: Optional[str] = Query(None, description="Filter by algorithm (e.g. RSA-2048, ECDSA-secp256r1, ML-DSA-44)"),
    quantum_status: Optional[str] = Query(None, description="Filter by quantum status (VULNERABLE, QUANTUM_RESISTANT, UNKNOWN)"),
    is_ca: Optional[bool] = Query(None, description="Filter by CA certificate flag"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
):
    """Lists reusable certificates and keys with algorithm, quantum status, and CA filters."""
    query = db.query(Certificate)

    if algorithm:
        query = query.filter(Certificate.algorithm == algorithm)
    if quantum_status:
        query = query.filter(Certificate.quantum_status == quantum_status)
    if is_ca is not None:
        query = query.filter(Certificate.is_ca == is_ca)

    total = query.count()
    items = query.order_by(Certificate.algorithm.asc()).offset(pagination.offset).limit(pagination.page_size).all()
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/{fingerprint}", response_model=CertificateResponse)
def get_certificate(
    fingerprint: str,
    db: Session = Depends(get_db),
):
    """Retrieves certificate metadata by fingerprint."""
    cert = db.query(Certificate).filter(Certificate.fingerprint == fingerprint).first()
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate with fingerprint '{fingerprint}' not found.",
        )
    return cert
