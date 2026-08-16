"""
Pydantic schemas for Dependency Graph Nodes and Edges.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class DependencyNodeResponse(BaseModel):
    """Schema representing a node in the dependency graph."""
    id: str
    node_id: str
    node_type: str
    name: str
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}


class DependencyEdgeResponse(BaseModel):
    """Schema representing a directed edge in the dependency graph."""
    id: str
    source_id: str
    target_id: str
    edge_type: str
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}


class GraphResponse(BaseModel):
    """Schema representing a complete or subgraph structure."""
    scan_id: Optional[str] = None
    artifact_id: Optional[str] = None
    nodes: List[DependencyNodeResponse]
    edges: List[DependencyEdgeResponse]
    statistics: Optional[Dict[str, Any]] = None
