from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class GraphNodeModel(BaseModel):
    id: str = Field(..., min_length=1, description="Node unique identifier")
    type: str = Field(..., description="Device classification: ROUTER, SWITCH, SERVER, etc.")
    label: str = Field(..., description="Human-readable node label or hostname")
    zone: str = Field(default="INTERNAL", description="Network security zone: DMZ, INTERNAL, etc.")
    state: str = Field(default="ACTIVE", description="Operational status: ACTIVE, DEGRADED, etc.")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class GraphEdgeModel(BaseModel):
    id: str = Field(..., min_length=1, description="Connection unique identifier")
    source: str = Field(..., min_length=1, description="Originating node ID")
    target: str = Field(..., min_length=1, description="Destination node ID")
    protocol: str = Field(default="TCP", description="Framing or transport protocol")
    status: str = Field(default="ACTIVE", description="Link operational status: ACTIVE, BLOCKED, etc.")
    weight: float = Field(default=1.0, ge=0.0, description="Cost metric (latency/inverse bandwidth)")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class GraphNeighborsResult(BaseModel):
    node_id: str
    inbound_neighbors: List[str]
    outbound_neighbors: List[str]
    all_neighbors: List[str]
    in_degree: int
    out_degree: int

class GraphSnapshotModel(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    node_count: int
    edge_count: int
    nodes: List[GraphNodeModel]
    edges: List[GraphEdgeModel]