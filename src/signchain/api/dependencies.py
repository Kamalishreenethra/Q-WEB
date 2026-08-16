"""
FastAPI route dependencies and pagination handlers for SignChain API.
"""
from typing import Generator
from fastapi import Query
from sqlalchemy.orm import Session

from signchain.db.session import get_db

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50


class PaginationParams:
    """Dependency for extracting and validating pagination parameters."""
    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number (1-indexed)"),
        page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Number of items per page"),
    ):
        self.page = page
        self.page_size = page_size
        self.offset = (page - 1) * page_size
