from enum import Enum
import ipaddress
import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone

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

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

class NetworkInterfaceConfig(BaseModel):
    interface_id: str = Field(..., min_length=1)
    ip_address: str = Field(..., description="IPv4 or IPv6 address")
    mac_address: str = Field(..., description="EUI-48 MAC address")
    subnet_cidr: str = Field(default="192.168.1.0/24")
    is_up: bool = True

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            # Allow 0.0.0.0 for unnumbered switch/bridge interfaces
            if v == "0.0.0.0":
                return v
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