from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.three_d_twin_contract import Vector3D, MeshArchetypeEnum

class SelectionStateEnum(str, Enum):
    UNSELECTED = "UNSELECTED"
    HOVERED = "HOVERED"
    SELECTED = "SELECTED"
    HIGHLIGHTED = "HIGHLIGHTED"
    HIDDEN = "HIDDEN"

class LabelDisplayMode(str, Enum):
    HOSTNAME_ONLY = "HOSTNAME_ONLY"
    TYPE_AND_HOSTNAME = "TYPE_AND_HOSTNAME"
    FULL_TELEMETRY = "FULL_TELEMETRY"

class LabelFilterOption(str, Enum):
    ALL = "ALL"
    SERVERS = "SERVERS"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    CLIENTS = "CLIENTS"
    AT_RISK = "AT_RISK"

class Device3DLabel(BaseModel):
    labelId: str = Field(default_factory=lambda: f"LBL-{uuid.uuid4().hex[:6].upper()}")
    deviceId: str
    hostname: str
    deviceType: str
    ipAddress: str
    riskScore: float
    securityState: str
    worldPosition: Vector3D
    isVisible: bool = True
    displayMode: LabelDisplayMode = LabelDisplayMode.TYPE_AND_HOSTNAME

class Device3DMeshMetadata(BaseModel):
    deviceId: str
    hostname: str
    archetype: MeshArchetypeEnum
    zone: str
    position: Vector3D
    boundingRadius: float = 1.5
    selectionState: SelectionStateEnum = SelectionStateEnum.UNSELECTED
    baseColorHex: str = "#3B82F6"
    emissiveColorHex: str = "#000000"
    isSelectable: bool = True
    label: Device3DLabel

class DeviceInspectionDetail3D(BaseModel):
    deviceId: str
    hostname: str
    deviceType: str
    ipAddress: str
    macAddress: str
    os: str
    interfaces: List[str] = Field(default_factory=lambda: ["eth0"])
    services: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    currentState: str
    securityState: str
    riskScore: float
    riskLevel: RiskLevelTier
    vulnerabilitiesCount: int
    vulnerabilities: List[str] = Field(default_factory=list)
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DeviceRendererSnapshot(BaseModel):
    totalDevicesRendered: int
    selectedDeviceId: Optional[str] = None
    focusedDeviceId: Optional[str] = None
    labelsVisible: bool = True
    activeLabelDisplayMode: LabelDisplayMode = LabelDisplayMode.TYPE_AND_HOSTNAME
    devices: Dict[str, Device3DMeshMetadata] = Field(default_factory=dict)