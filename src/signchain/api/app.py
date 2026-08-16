"""
FastAPI Application Entrypoint for SignChain REST API.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from signchain.api.routes import (
    health_router,
    scans_router,
    artifacts_router,
    certificates_router,
    risk_router,
    pqc_router,
    migration_router,
    graph_router,
)


def create_app() -> FastAPI:
    """Creates and configures the FastAPI application."""
    app = FastAPI(
        title="SignChain Post-Quantum Cryptographic Migration API",
        description="Automated Discovery, Cryptographic Classification, and Migration Planning for Post-Quantum Code Signing in Software Supply Chains.",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS configuration for future React/Vite dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configurable in production hardening phase
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register Routers
    app.include_router(health_router)
    app.include_router(scans_router)
    app.include_router(artifacts_router)
    app.include_router(certificates_router)
    app.include_router(risk_router)
    app.include_router(pqc_router)
    app.include_router(migration_router)
    app.include_router(graph_router)

    return app


app = create_app()
