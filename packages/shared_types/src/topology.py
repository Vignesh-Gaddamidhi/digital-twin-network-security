from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid

class ConnectionEntity(BaseModel):
    connection_id: str = Field(default_factory=lambda: f"conn-{uuid.uuid4().hex[:10]}")
    source_device: str
    destination_device: str
    connection_type: str = "PHYSICAL_LINK" # PHYSICAL_LINK, LOGICAL_ROUTED, SERVICE_SESSION
    protocol: str = "ETHERNET"             # ETHERNET, IP, TCP, UDP
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    status: str = "ACTIVE"                 # ACTIVE, DEGRADED, BLOCKED, TERMINATED
    latency_ms: float = 1.0
    bandwidth_mbps: float = 1000.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

class TopologyValidationResult(BaseModel):
    is_connected: bool
    path_hops: List[str] = Field(default_factory=list)
    hop_count: int = 0
    total_latency_ms: float = 0.0
    traversed_devices: List[str] = Field(default_factory=list)

class NetworkTopologySchema(BaseModel):
    topology_id: str = Field(default_factory=lambda: f"topo-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    device_count: int
    connection_count: int
    connections: List[ConnectionEntity]
    subnets_count: int
    critical_bridges: List[str] = Field(default_factory=list) # Articulation points