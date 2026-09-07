from enum import Enum
import ipaddress
import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class DeviceTypeEnum(str, Enum):
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    SERVER = "SERVER"
    CLIENT = "CLIENT"
    FIREWALL = "FIREWALL"
    LOAD_BALANCER = "LOAD_BALANCER"
    IDS = "IDS"
    IPS = "IPS"
    VPN_GATEWAY = "VPN_GATEWAY"
    DATABASE = "DATABASE"
    DNS_SERVER = "DNS_SERVER"

class NetworkZoneEnum(str, Enum):
    INTERNAL = "INTERNAL"
    DMZ = "DMZ"
    EXTERNAL = "EXTERNAL"
    MANAGEMENT = "MANAGEMENT"
    UNKNOWN = "UNKNOWN"

class RouteStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    UNREACHABLE = "UNREACHABLE"

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

class RouteEntryModel(BaseModel):
    id: str = Field(default_factory=lambda: f"rt-{uuid.uuid4().hex[:8]}")
    destination: str = Field(..., description="Target CIDR (e.g., 192.168.1.0/24 or 0.0.0.0/0)")
    nextHop: Optional[str] = Field(default=None, description="Next hop IP or None for DIRECT link")
    interface: str = Field(..., description="Egress interface ID (e.g., eth0)")
    metric: int = Field(default=1, ge=0, description="Routing metric / administrative distance")
    status: RouteStatusEnum = Field(default=RouteStatusEnum.ACTIVE)

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR network format: '{v}'")
        return v

    @field_validator("nextHop")
    @classmethod
    def validate_next_hop(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.upper() != "DIRECT":
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid next hop IP address: '{v}'")
        return v

class ForwardingDecisionResult(BaseModel):
    destination_ip: str
    matched_route: Optional[RouteEntryModel] = None
    next_hop: str
    egress_interface: str
    is_direct: bool
    path_resolved: bool
    explanation: str

# Legacy RouteEntryConfig alias for compatibility
RouteEntryConfig = RouteEntryModel

class NetworkInterfaceConfig(BaseModel):
    interface_id: str = Field(..., min_length=1)
    ip_address: str = Field(..., description="IPv4 or IPv6 address")
    mac_address: str = Field(..., description="EUI-48 MAC address")
    subnet_cidr: str = Field(default="192.168.1.0/24")
    status: str = Field(default="UP")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if v != "0.0.0.0":
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address format: '{v}'")
        return v

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not MAC_REGEX.match(v):
            raise ValueError(f"Invalid MAC address format: '{v}'. Must be XX:XX:XX:XX:XX:XX")
        return v.upper()

class NetworkDeviceModel(BaseModel):
    id: str = Field(..., min_length=2, pattern=r"^[a-zA-Z0-9_\-]+$", description="Unique alphanumeric identifier")
    hostname: str = Field(..., min_length=2, pattern=r"^[a-zA-Z0-9_\-]+$", description="RFC 1123 compliant hostname")
    type: DeviceTypeEnum
    role: str = Field(default="GENERIC_NODE")
    ipAddresses: List[str] = Field(default_factory=list)
    macAddresses: List[str] = Field(default_factory=list)
    interfaces: List[NetworkInterfaceConfig] = Field(default_factory=list)
    routes: List[RouteEntryModel] = Field(default_factory=list)
    operatingSystem: str = Field(default="Linux")
    services: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    connections: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    networkZone: NetworkZoneEnum = Field(default=NetworkZoneEnum.INTERNAL)
    currentState: str = Field(default="ONLINE")
    securityState: str = Field(default="NORMAL")
    riskScore: float = Field(default=0.0, ge=0.0, le=100.0)
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("ipAddresses", mode="before")
    @classmethod
    def validate_ips(cls, ips: List[str]) -> List[str]:
        for ip in ips:
            if ip != "0.0.0.0":
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    raise ValueError(f"Invalid IP address in list: '{ip}'")
        return ips

    @field_validator("macAddresses", mode="before")
    @classmethod
    def validate_macs(cls, macs: List[str]) -> List[str]:
        cleaned = []
        for mac in macs:
            if not MAC_REGEX.match(mac):
                raise ValueError(f"Invalid MAC address in list: '{mac}'")
            cleaned.append(mac.upper())
        return cleaned

class ConfigurationHistoryRecord(BaseModel):
    history_id: str = Field(default_factory=lambda: f"cfg-{uuid.uuid4().hex[:8]}")
    device_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action: str
    field_changed: str
    previous_value: Any
    new_value: Any
    operator: str = "SYSTEM_ADMIN"
    reason: str = "Operational reconfiguration"