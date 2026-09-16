from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, model_validator

class ConnectionTypeEnum(str, Enum):

    DIRECT = "DIRECT"
    LOGICAL = "LOGICAL"
    ROUTED = "ROUTED"
    BRIDGED = "BRIDGED"
    WIRELESS = "WIRELESS"
    TUNNEL = "TUNNEL"
    PHYSICAL = "PHYSICAL"
    VIRTUAL = "VIRTUAL"
    VPN = "VPN"

class ProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    IP = "IP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"

class ConnectionStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"

class NetworkConnectionModel(BaseModel):
    id: str = Field(default="")
    connection_id: Optional[str] = None
    sourceDevice: str = Field(default="")
    source_device: Optional[str] = None
    destinationDevice: str = Field(default="")
    destination_device: Optional[str] = None
    protocol: str = Field(default="TCP")
    port: Optional[int] = None
    connection_type: Optional[str] = Field(default="DIRECT")
    connectionType: Optional[str] = Field(default="DIRECT")
    status: ConnectionStatusEnum = Field(default=ConnectionStatusEnum.ACTIVE)
    bandwidth_mbps: float = Field(default=1000.0)
    latency_ms: float = Field(default=1.0)
    packet_loss_pct: float = Field(default=0.0)

    @model_validator(mode="before")
    @classmethod
    def _compat_conn(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            cid = d.get("id") or d.get("connection_id") or ""
            d["id"] = cid
            d["connection_id"] = cid

            src = d.get("sourceDevice") or d.get("source_device") or d.get("source") or ""
            d["sourceDevice"] = src
            d["source_device"] = src

            dst = d.get("destinationDevice") or d.get("destination_device") or d.get("destination") or ""
            d["destinationDevice"] = dst
            d["destination_device"] = dst

            ctype = d.get("connection_type") or d.get("connectionType") or "DIRECT"
            d["connection_type"] = ctype
            d["connectionType"] = ctype

            return d
        return data

ConnectionEntity = NetworkConnectionModel

class TopologyValidationResult(BaseModel):
    is_valid: bool = True
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    isolated_nodes: List[str] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    traversed_devices: List[str] = Field(default_factory=list)
    path_hops: List[str] = Field(default_factory=list)
    hop_count: int = 0
    total_latency_ms: float = 0.0
    path_found: bool = True

    @model_validator(mode="before")
    @classmethod
    def _compat_hops(cls, data):
        if isinstance(data, dict):
            d = dict(data)
            hops = d.get("path_hops") or d.get("traversed_devices") or []
            d["path_hops"] = hops
            d["traversed_devices"] = hops
            return d
        return data

class TopologySummarySnapshotModel(BaseModel):
    total_devices: int = 0
    total_connections: int = 0
    active_connections: int = 0
    degraded_connections: int = 0
    blocked_connections: int = 0
    zones_represented: List[str] = Field(default_factory=list)
    average_latency_ms: float = 0.0
    isolated_nodes: List[str] = Field(default_factory=list)
    is_valid: bool = True
    errors: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _compat_summary(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            if "total_nodes" in d and "total_devices" not in d:
                d["total_devices"] = d["total_nodes"]
            if "total_edges" in d and "total_connections" not in d:
                d["total_connections"] = d["total_edges"]
            return d
        return data

TopologySummarySnapshot = TopologySummarySnapshotModel
