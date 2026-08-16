"""
Database session management and engine configuration for SignChain.
Supports SQLite (development/offline default) and PostgreSQL (production).
"""
import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Environment-driven database URL with secure SQLite default
DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.getcwd(), "signchain.db"))
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# SQLite connection args for threading support
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(target_engine=None) -> None:
    """Initializes tables for development/testing if migrations have not been applied."""
    from signchain.db.base import Base
    import signchain.db.models  # Ensure all models are registered
    
    eng = target_engine or engine
    Base.metadata.create_all(bind=eng)
