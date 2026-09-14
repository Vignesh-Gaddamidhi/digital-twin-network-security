from enum import Enum
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field

class NetworkZoneEnum(str, Enum):
    INTERNET = "INTERNET"
    DMZ = "DMZ"
    INTERNAL = "INTERNAL"
    DATABASE = "DATABASE"
    MANAGEMENT = "MANAGEMENT"
    UNKNOWN = "UNKNOWN"

class ReachabilityStateEnum(str, Enum):
    REACHABLE = "REACHABLE"
    RESTRICTED = "RESTRICTED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"

class SecurityControlPolicy(BaseModel):
    controlId: str
    name: str
    sourceZone: NetworkZoneEnum
    destinationZone: NetworkZoneEnum
    allowedPorts: List[int] = Field(default_factory=list)
    allowedProtocols: List[str] = Field(default_factory=lambda: ["TCP", "UDP"])
    reachabilityState: ReachabilityStateEnum = ReachabilityStateEnum.REACHABLE
    description: str = ""

# Standard baseline firewall segmentation policies between zones
DEFAULT_SECURITY_POLICIES: List[SecurityControlPolicy] = [
    SecurityControlPolicy(
        controlId="FW-RULE-01",
        name="Internet to DMZ Web Ingress",
        sourceZone=NetworkZoneEnum.INTERNET,
        destinationZone=NetworkZoneEnum.DMZ,
        allowedPorts=[80, 443],
        reachabilityState=ReachabilityStateEnum.REACHABLE,
        description="Allows public HTTP/HTTPS access to DMZ Web Servers."
    ),
    SecurityControlPolicy(
        controlId="FW-RULE-02",
        name="Internal to DMZ Management",
        sourceZone=NetworkZoneEnum.INTERNAL,
        destinationZone=NetworkZoneEnum.DMZ,
        allowedPorts=[22, 80, 443],
        reachabilityState=ReachabilityStateEnum.REACHABLE,
        description="Permits workstations to access DMZ web and SSH services."
    ),
    SecurityControlPolicy(
        controlId="FW-RULE-03",
        name="DMZ to Database Access",
        sourceZone=NetworkZoneEnum.DMZ,
        destinationZone=NetworkZoneEnum.DATABASE,
        allowedPorts=[3306, 5432],
        reachabilityState=ReachabilityStateEnum.REACHABLE,
        description="Allows DMZ web tier to communicate with database instances on standard SQL ports."
    ),
    SecurityControlPolicy(
        controlId="FW-RULE-04",
        name="Internal to Database Direct Blocking",
        sourceZone=NetworkZoneEnum.INTERNAL,
        destinationZone=NetworkZoneEnum.DATABASE,
        allowedPorts=[],
        reachabilityState=ReachabilityStateEnum.BLOCKED,
        description="Direct corporate client access to database tier is blocked by default."
    )
]