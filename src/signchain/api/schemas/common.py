"""
Common Pydantic schemas and pagination models for SignChain API.
"""
from typing import Generic, List, TypeVar, Optional, Any
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated list container."""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class StatusMessage(BaseModel):
    """Standard status/health response model."""
    status: str
    message: Optional[str] = None
    version: str = "0.1.0"
