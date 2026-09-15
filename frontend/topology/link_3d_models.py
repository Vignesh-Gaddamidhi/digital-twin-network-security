from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from frontend.topology.three_d_twin_contract import Vector3D

class LinkStateEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"

class TrafficFlowDirectionEnum(str, Enum):
    FORWARD = "FORWARD"    # Source -> Destination
    REVERSE = "REVERSE"    # Destination -> Source

class TrafficProtocolType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"

class TrafficParticleState(BaseModel):
    particleId: str = Field(default_factory=lambda: f"PKT-{uuid.uuid4().hex[:6].upper()}")
    linkId: str
    protocol: TrafficProtocolType
    direction: TrafficFlowDirectionEnum = TrafficFlowDirectionEnum.FORWARD
    progressT: float = 0.0  # 0.0 to 1.0 along the spline
    speed: float = 0.02
    colorHex: str = "#3B82F6"
    size: float = 0.8
    bytesTransferred: int = 1024

class NetworkLink3D(BaseModel):
    linkId: str
    connectionId: str
    sourceDeviceId: str
    destinationDeviceId: str
    protocol: TrafficProtocolType
    sourcePort: int
    destinationPort: int
    interfaceName: str = "eth0"
    status: LinkStateEnum = LinkStateEnum.ACTIVE
    sourcePos: Vector3D
    destinationPos: Vector3D
    midArcPos: Vector3D
    isReachable: bool = True
    isTraversedInAttackPath: bool = False
    activeParticles: List[TrafficParticleState] = Field(default_factory=list)
    trafficRateBps: float = 1024.0

class LinkRendererSnapshot(BaseModel):
    totalLinks: int
    activeLinksCount: int
    blockedLinksCount: int
    totalActiveParticles: int
    maxParticleCapacity: int = 500
    links: Dict[str, NetworkLink3D] = Field(default_factory=dict)