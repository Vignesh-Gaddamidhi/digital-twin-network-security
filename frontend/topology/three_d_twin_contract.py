from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class MeshArchetypeEnum(str, Enum):
    FIREWALL = "FIREWALL"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    SERVER = "SERVER"
    DATABASE = "DATABASE"
    DNS = "DNS"
    CLIENT = "CLIENT"
    ATTACKER = "ATTACKER"
    GENERIC_DEVICE = "GENERIC_DEVICE"

class Vector3D(BaseModel):
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

class CanonicalTwinDevice(BaseModel):
    deviceId: str
    hostname: str
    deviceType: str
    zone: str
    ipAddresses: List[str]
    macAddress: str
    os: str
    services: List[str]
    openPorts: List[int]
    securityState: str
    riskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    vulnerabilities: List[str]
    isCriticalAsset: bool = False
    isIsolated: bool = False

class DeviceVisual3DState(BaseModel):
    deviceId: str
    archetype: MeshArchetypeEnum
    position: Vector3D
    rotation: Vector3D = Field(default_factory=Vector3D)
    scale: Vector3D = Field(default_factory=lambda: Vector3D(x=1.0, y=1.0, z=1.0))
    colorHex: str = "#3B82F6"
    emissiveHex: str = "#000000"
    isSelected: bool = False
    isHighlighted: bool = False
    isVisible: bool = True
    particlePulseRate: float = 1.0
    boundingRadius: float = 1.5

class LinkVisual3DState(BaseModel):
    linkId: str
    sourceDeviceId: str
    targetDeviceId: str
    sourcePos: Vector3D
    targetPos: Vector3D
    protocol: str
    isReachable: bool = True
    isBlocked: bool = False
    isTraversedInAttackPath: bool = False
    trafficParticleCount: int = 10
    colorHex: str = "#60A5FA"

class Unified3DTwinState(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    devices: List[CanonicalTwinDevice] = Field(default_factory=list)
    visualStates: Dict[str, DeviceVisual3DState] = Field(default_factory=dict)
    links: List[LinkVisual3DState] = Field(default_factory=list)
    activeAttackPathDeviceIds: List[str] = Field(default_factory=list)
    totalDevices: int = 0
    totalLinks: int = 0

class DeviceTo3DMapper:
    """Deterministic mapper converting Canonical Twin types to 3D Visual Archetypes and Layout Coordinates."""

    ZONE_Z_OFFSETS = {
        "INTERNET": -150.0,
        "DMZ": -50.0,
        "INTERNAL": 50.0,
        "DATABASE": 150.0,
        "INFRA": 0.0
    }

    ARCHETYPE_COLORS = {
        MeshArchetypeEnum.FIREWALL: "#EF4444",
        MeshArchetypeEnum.ROUTER: "#F59E0B",
        MeshArchetypeEnum.SWITCH: "#10B981",
        MeshArchetypeEnum.SERVER: "#3B82F6",
        MeshArchetypeEnum.DATABASE: "#8B5CF6",
        MeshArchetypeEnum.DNS: "#06B6D4",
        MeshArchetypeEnum.CLIENT: "#6B7280",
        MeshArchetypeEnum.ATTACKER: "#DC2626",
        MeshArchetypeEnum.GENERIC_DEVICE: "#9CA3AF"
    }

    @classmethod
    def map_archetype(cls, raw_type: str) -> MeshArchetypeEnum:
        t = raw_type.upper()
        if "FIREWALL" in t:
            return MeshArchetypeEnum.FIREWALL
        elif "ROUTER" in t:
            return MeshArchetypeEnum.ROUTER
        elif "SWITCH" in t:
            return MeshArchetypeEnum.SWITCH
        elif "DATABASE" in t or "DB" in t or "SQL" in t:
            return MeshArchetypeEnum.DATABASE
        elif "DNS" in t:
            return MeshArchetypeEnum.DNS
        elif "WEB" in t or "SERVER" in t or "APP" in t:
            return MeshArchetypeEnum.SERVER
        elif "CLIENT" in t or "HOST" in t or "WORKSTATION" in t:
            return MeshArchetypeEnum.CLIENT
        elif "ATTACKER" in t:
            return MeshArchetypeEnum.ATTACKER
        return MeshArchetypeEnum.GENERIC_DEVICE

    @classmethod
    def compute_initial_position(cls, zone: str, index_in_zone: int, total_in_zone: int) -> Vector3D:
        z = cls.ZONE_Z_OFFSETS.get(zone.upper(), 0.0)
        spacing_x = 40.0
        start_x = -((total_in_zone - 1) * spacing_x) / 2.0
        x = start_x + (index_in_zone * spacing_x)
        y = 0.0  # Planar baseline in 3D scene
        return Vector3D(x=round(x, 2), y=round(y, 2), z=round(z, 2))