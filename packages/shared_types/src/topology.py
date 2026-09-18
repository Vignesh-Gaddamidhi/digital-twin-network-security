from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field, model_validator

class ConnectionTypeEnum(str, Enum):
    PHYSICAL = "PHYSICAL"
    LOGICAL = "LOGICAL"
    NETWORK = "NETWORK"
    SERVICE = "SERVICE"

class ConnectionStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CLOSED = "CLOSED"

class ProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"

class NetworkConnectionModel(BaseModel):
    id: str
    sourceDevice: str
    destinationDevice: str
    protocol: Optional[ProtocolEnum] = ProtocolEnum.TCP
    destinationPort: Optional[int] = Field(default=None, ge=1, le=65535)
    sourcePort: Optional[int] = Field(default=None, ge=1, le=65535)
    connectionType: Optional[ConnectionTypeEnum] = ConnectionTypeEnum.PHYSICAL
    status: Optional[ConnectionStatusEnum] = ConnectionStatusEnum.ACTIVE
    bandwidth: Optional[float] = 1000.0
    latency: Optional[float] = 0.5
    lastUpdated: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_no_self_loop(self):
        if self.sourceDevice and self.destinationDevice:
            if self.sourceDevice.strip() == self.destinationDevice.strip():
                raise ValueError(f"Self-loop connection rejected: {self.sourceDevice} cannot connect to itself.")
        return self

class ConnectionEntity(BaseModel):
    id: str
    connection_id: Optional[str] = None
    source_device: str
    destination_device: str
    protocol: str = "TCP"
    destination_port: Optional[int] = None
    connection_type: str = "NETWORK"
    status: str = "ACTIVE"
    bandwidth: float = 1000.0
    latency: float = 0.5
    latency_ms: Optional[float] = None
    bandwidth_mbps: Optional[float] = 1000.0

    @model_validator(mode="before")
    @classmethod
    def _normalize_connection(cls, data: Any) -> Any:
        if isinstance(data, dict):
            cid = data.get("connection_id") or data.get("id")
            if cid:
                data["id"] = cid
                data["connection_id"] = cid
            
            lat = data.get("latency") or data.get("latency_ms")
            if lat is not None:
                data["latency"] = float(lat)
                data["latency_ms"] = float(lat)
        return data

    @model_validator(mode="after")
    def _sync_connection_attrs(self):
        if not self.connection_id:
            self.connection_id = self.id
        if self.latency_ms is None:
            self.latency_ms = self.latency
        if self.bandwidth_mbps is None:
            self.bandwidth_mbps = self.bandwidth
        else:
            self.bandwidth = self.bandwidth_mbps
        return self


class TopologyValidationResult(BaseModel):
    is_valid: bool = True
    is_connected: bool = True
    hop_count: int = 0
    traversed_devices: List[str] = Field(default_factory=list)
    path_hops: List[str] = Field(default_factory=list)
    total_latency_ms: float = 0.0
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class PathfindingResult(BaseModel):
    is_connected: bool = False
    hop_count: int = 0
    path_hops: List[str] = Field(default_factory=list)
    traversed_devices: List[str] = Field(default_factory=list)
    total_latency_ms: float = 0.0

class TopologySummarySnapshotModel(BaseModel):
    nodes: int = 0
    edges: int = 0
    zones: int = 0
    activeDevices: int = 0
    inactiveDevices: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())