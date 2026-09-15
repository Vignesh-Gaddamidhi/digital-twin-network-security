from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class TopologyNodeState(str, Enum):
    NORMAL = "NORMAL"
    MONITORED = "MONITORED"
    SUSPICIOUS = "SUSPICIOUS"
    AT_RISK = "AT_RISK"
    COMPROMISED = "COMPROMISED"
    ISOLATED = "ISOLATED"
    UNKNOWN = "UNKNOWN"

class CanvasCoordinates(BaseModel):
    x: float
    y: float

class TopologyNodeVisual(BaseModel):
    id: str
    deviceId: str
    hostname: str
    label: str
    nodeType: str
    zone: str
    ipAddress: str
    macAddress: Optional[str] = None
    os: Optional[str] = None
    securityState: TopologyNodeState
    riskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    openPorts: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    vulnerabilitiesCount: int = 0
    activeVulnerabilities: List[str] = Field(default_factory=list)
    position: CanvasCoordinates
    isTarget: bool = False
    isAttacker: bool = False

class TopologyEdgeVisual(BaseModel):
    id: str
    source: str
    target: str
    protocol: str
    destinationPort: int
    service: str
    status: str            # ACTIVE, ATTEMPTED, BLOCKED
    reachability: str      # REACHABLE, RESTRICTED, BLOCKED
    hasActiveTraffic: bool = True
    trafficRateBps: float = 1024.0
    securityControl: Optional[str] = None

class SubnetZoneBoundary(BaseModel):
    zoneId: str
    name: str
    cidr: str
    zoneType: str
    colorTheme: str
    bounds: Dict[str, float]  # x, y, width, height

class ViewportTransform(BaseModel):
    zoomLevel: float = 1.0
    panX: float = 0.0
    panY: float = 0.0
    minZoom: float = 0.2
    maxZoom: float = 3.0

class LiveTopologySnapshot(BaseModel):
    nodes: List[TopologyNodeVisual]
    edges: List[TopologyEdgeVisual]
    zones: List[SubnetZoneBoundary]
    viewport: ViewportTransform = Field(default_factory=ViewportTransform)
    totalNodes: int
    totalEdges: int
    activeTrafficConnections: int
    lastRenderedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class NodeDetailDrawer(BaseModel):
    deviceId: str
    hostname: str
    zone: str
    ipAddress: str
    macAddress: str
    os: str
    deviceType: str
    securityState: TopologyNodeState
    riskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    openPorts: List[int]
    services: List[str]
    vulnerabilitiesCount: int
    vulnerabilities: List[str]
    activeConnectionsCount: int
    connectedPeers: List[str]
    isolationStatus: bool