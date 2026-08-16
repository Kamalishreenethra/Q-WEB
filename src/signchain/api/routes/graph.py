"""
Dependency Graph API routes.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from signchain.api.schemas.graph import GraphResponse, DependencyNodeResponse, DependencyEdgeResponse
from signchain.db.models import DependencyNode, DependencyEdge, Artifact
from signchain.db.session import get_db

router = APIRouter(prefix="/graph", tags=["Dependency Graph"])


@router.get("/{artifact_id}", response_model=GraphResponse)
def get_graph_by_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves the dependency graph nodes and edges associated with an artifact's scan."""
    artifact = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact with ID '{artifact_id}' not found.",
        )

    scan_id = artifact.scan_id
    nodes = db.query(DependencyNode).filter(DependencyNode.scan_id == scan_id).all()
    edges = db.query(DependencyEdge).filter(DependencyEdge.scan_id == scan_id).all()

    return GraphResponse(
        scan_id=scan_id,
        artifact_id=artifact_id,
        nodes=[DependencyNodeResponse.model_validate(n) for n in nodes],
        edges=[DependencyEdgeResponse.model_validate(e) for e in edges],
        statistics={
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
    )


@router.get("/scan/{scan_id}", response_model=GraphResponse)
def get_graph_by_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves all dependency graph nodes and edges for a scan execution."""
    nodes = db.query(DependencyNode).filter(DependencyNode.scan_id == scan_id).all()
    edges = db.query(DependencyEdge).filter(DependencyEdge.scan_id == scan_id).all()

    if not nodes and not edges:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No graph found for scan ID '{scan_id}'.",
        )

    return GraphResponse(
        scan_id=scan_id,
        artifact_id=None,
        nodes=[DependencyNodeResponse.model_validate(n) for n in nodes],
        edges=[DependencyEdgeResponse.model_validate(e) for e in edges],
        statistics={
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
    )
