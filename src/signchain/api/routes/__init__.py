"""
API Route Handlers for SignChain REST API.
"""
from signchain.api.routes.health import router as health_router
from signchain.api.routes.scans import router as scans_router
from signchain.api.routes.artifacts import router as artifacts_router
from signchain.api.routes.certificates import router as certificates_router
from signchain.api.routes.risk import router as risk_router
from signchain.api.routes.pqc import router as pqc_router
from signchain.api.routes.migration import router as migration_router
from signchain.api.routes.graph import router as graph_router

__all__ = [
    "health_router",
    "scans_router",
    "artifacts_router",
    "certificates_router",
    "risk_router",
    "pqc_router",
    "migration_router",
    "graph_router",
]
