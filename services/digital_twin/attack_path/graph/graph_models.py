from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class NodeTypeEnum(str, Enum):
    ATTACKER = "ATTACKER"
    DEVICE = "DEVICE"
    CLIENT = "CLIENT"
    SERVER = "SERVER"
    WEB_SERVER = "WEB_SERVER"
    DATABASE = "DATABASE"
    DNS_SERVER = "DNS_SERVER"
    ROUTER = "ROUTER"
    FIREWALL = "FIREWALL"
    SWITCH = "SWITCH"
    TARGET = "TARGET"
    UNKNOWN = "UNKNOWN"

class PathStatusEnum(str, Enum):
    POSSIBLE = "POSSIBLE"
    BLOCKED = "BLOCKED"
    PARTIALLY_REACHABLE = "PARTIALLY_REACHABLE"
    UNVERIFIED = "UNVERIFIED"
    ACTIVE_SIMULATION = "ACTIVE_SIMULATION"
    COMPLETED = "COMPLETED"
    INVALID = "INVALID"

class AttackPathNode(BaseModel):
    nodeId: str
    deviceId: str
    nodeType: NodeTypeEnum = NodeTypeEnum.DEVICE
    hostname: str
    ipAddresses: List[str] = Field(default_factory=list)
    deviceType: str = "Standard Node"
    zone: str = "DEFAULT_ZONE"  # e.g. INTERNET, DMZ, USER_LAN, SECURE_DATA
    assetCriticality: str = "MEDIUM"
    vulnerabilities: List[str] = Field(default_factory=list)
    exposedPorts: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    securityState: str = "NORMAL"
    riskScore: float = 0.0
    reachable: bool = True

    @field_validator("nodeId")
    @classmethod
    def validate_node_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("nodeId cannot be empty or whitespace.")
        return v.strip()

class AttackPathEdge(BaseModel):
    edgeId: str = Field(default_factory=lambda: f"EDGE-{uuid.uuid4().hex[:8].upper()}")
    sourceNode: str
    destinationNode: str
    connectionId: str = "CONN-DEFAULT"
    protocol: str = "TCP"
    sourcePort: Optional[int] = None
    destinationPort: int = 80
    service: str = "HTTP"
    reachable: bool = True
    trustRelationship: bool = False
    securityControl: Optional[str] = None  # e.g., "FW-DMZ-ACL-01", "INGRESS-RATE-LIMIT"
    vulnerabilityExposure: Optional[str] = None
    riskContribution: float = 0.0
    status: str = "ACTIVE"

    @field_validator("sourceNode", "destinationNode")
    @classmethod
    def validate_endpoints(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Edge endpoints cannot be empty.")
        return v.strip()

class AttackPath(BaseModel):
    pathId: str = Field(default_factory=lambda: f"PATH-{uuid.uuid4().hex[:8].upper()}")
    attacker: str
    entryNode: str
    targetNode: str
    nodes: List[str]  # Ordered sequence of nodeIds: [Attacker, Entry, ..., Target]
    edges: List[str] = Field(default_factory=list)  # Ordered sequence of edgeIds
    pathLength: int
    pathStatus: PathStatusEnum = PathStatusEnum.POSSIBLE
    reachability: bool = True
    pathRiskScore: float = 0.0
    pathRiskLevel: str = "LOW"
    vulnerabilities: List[str] = Field(default_factory=list)
    attackTechniques: List[str] = Field(default_factory=list)
    securityControls: List[str] = Field(default_factory=list)
    explanation: str = ""
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    analysisVersion: str = "1.0"

    def to_summary_string(self) -> str:
        chain = " -> ".join(self.nodes)
        return (
            f"AttackPath [{self.pathId}]: {chain}\n"
            f"Status: {self.pathStatus.value} | Length: {self.pathLength} hops | Risk: {self.pathRiskLevel} ({self.pathRiskScore:.1f}/100)\n"
            f"Target: {self.targetNode} | Entry: {self.entryNode}"
        )