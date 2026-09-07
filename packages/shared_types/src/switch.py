from enum import Enum
import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

class PortStatusEnum(str, Enum):
    UP = "UP"
    DOWN = "DOWN"
    BLOCKED = "BLOCKED"

class PortModeEnum(str, Enum):
    ACCESS = "ACCESS"
    TRUNK = "TRUNK"

class SwitchPortModel(BaseModel):
    port_number: int = Field(..., ge=1, le=128, description="Switch physical port number")
    status: PortStatusEnum = Field(default=PortStatusEnum.UP)
    mode: PortModeEnum = Field(default=PortModeEnum.ACCESS)
    vlan_id: int = Field(default=1, ge=1, le=4094, description="Default untagged access VLAN")
    connected_device_id: Optional[str] = Field(default=None)
    connected_mac: Optional[str] = Field(default=None)
    speed_mbps: float = Field(default=1000.0)

    @field_validator("connected_mac")
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            if not MAC_REGEX.match(v):
                raise ValueError(f"Invalid MAC format: '{v}'")
            return v.upper()
        return None

class MacTableEntryModel(BaseModel):
    mac_address: str = Field(...)
    port_number: int = Field(..., ge=1)
    vlan_id: int = Field(default=1)
    entry_type: str = Field(default="DYNAMIC")  # DYNAMIC, STATIC
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not MAC_REGEX.match(v):
            raise ValueError(f"Invalid MAC format: '{v}'")
        return v.upper()

class VlanModel(BaseModel):
    vlan_id: int = Field(..., ge=1, le=4094)
    name: str = Field(..., min_length=2)
    subnet: Optional[str] = Field(default=None, description="Optional IP subnet (e.g., 192.168.10.0/24)")
    member_ports: List[int] = Field(default_factory=list)
    member_devices: List[str] = Field(default_factory=list)

class Layer2FrameForwardResult(BaseModel):
    source_mac: str
    destination_mac: str
    vlan_id: int
    ingress_port: int
    forwarding_action: str  # FORWARD_UNICAST, FLOOD, DROP
    egress_ports: List[int]
    explanation: str