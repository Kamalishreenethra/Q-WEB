"""
Pydantic schemas for Certificates and signing keys.
"""
from typing import Optional
from pydantic import BaseModel


class CertificateResponse(BaseModel):
    """Schema representing reusable cryptographic certificate metadata."""
    fingerprint: str
    subject: str
    issuer: str
    serial_number: Optional[str] = None
    algorithm: str
    key_size: Optional[int] = None
    curve: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    quantum_status: str
    is_ca: bool

    model_config = {"from_attributes": True}
