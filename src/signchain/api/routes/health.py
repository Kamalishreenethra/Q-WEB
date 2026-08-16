"""
Health check and status API routes.
"""
from fastapi import APIRouter
from signchain.api.schemas.common import StatusMessage

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=StatusMessage)
def get_health():
    """Returns the operational status and version of SignChain backend."""
    return StatusMessage(
        status="HEALTHY",
        message="SignChain REST API is operational.",
        version="0.1.0",
    )
