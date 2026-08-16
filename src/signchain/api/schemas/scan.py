"""
Pydantic schemas for Scan history and ingestion.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScanResponse(BaseModel):
    """Schema representing an individual Scan record."""
    id: str
    timestamp: datetime
    scanner_version: str
    status: str
    duration_sec: float
    artifact_count: int
    error_count: int
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}


class ScanIngestionRequest(BaseModel):
    """Schema for direct scan result ingestion."""
    raw_result: Dict[str, Any]
    scanner_version: Optional[str] = "0.1.0"
