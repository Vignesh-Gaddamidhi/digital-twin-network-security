from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class ConnectionTypeEnum(str, Enum):
    PHYSICAL = "PHYSICAL"
    LOGICAL = "LOGICAL"
    NETWORK = "NETWORK"
    SERVICE = "SERVICE"

class ConnectionStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    TERMINATED = "TERMINATED"

class ProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ETHERNET = "ETHERNET"
    ANY = "ANY"

class NetworkConnectionModel(BaseModel):
    id: str = Field(..., min_length=2, description="Unique connection ID (e.g., conn-001)")
    sourceDevice: str = Field(..., min_length=1, description="Originating device ID")
    destinationDevice: str = Field(..., min_length=1, description="Target device ID")
    sourceInterface: Optional[str] = Field(default=None, description="Source NIC interface (e.g., eth0)")
    destinationInterface: Optional[str] = Field(default=None, description="Destination NIC interface (e.g., eth0)")
    protocol: ProtocolEnum = Field(default=ProtocolEnum.TCP)
    sourcePort: Optional[int] = Field(default=None, ge=1, le=65535)
    destinationPort: Optional[int] = Field(default=None, ge=1, le=65535)
    connectionType: ConnectionTypeEnum = Field(default=ConnectionTypeEnum.NETWORK)
    status: ConnectionStatusEnum = Field(default=ConnectionStatusEnum.ACTIVE)
    bandwidth: float = Field(default=1000.0, ge=0.0, description="Bandwidth line rate in Mbps")
    latency: float = Field(default=1.0, ge=0.0, description="Propagation latency in ms")
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("destinationDevice")
    @classmethod
    def check_no_self_loop(cls, v: str, info) -> str:
        if "sourceDevice" in info.data and v == info.data["sourceDevice"]:
            raise ValueError(f"Self-loop connections are not permitted: '{v}' -> '{v}'")
        return v

# Backward compatibility aliases for Twin Core
ConnectionEntity = NetworkConnectionModel

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
    connections: List[NetworkConnectionModel]
    subnets_count: int
    critical_bridges: List[str] = Field(default_factory=list)
class TopologySummarySnapshotModel(BaseModel):
    nodes: int
    edges: int
    zones: int
    activeDevices: int
    inactiveDevices: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())