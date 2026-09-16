from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field, model_validator

class DeviceTypeEnum(str, Enum):
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    FIREWALL = "FIREWALL"
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    CLIENT = "CLIENT"

class NetworkZoneEnum(str, Enum):
    EXTERNAL = "EXTERNAL"
    DMZ = "DMZ"
    INTERNAL = "INTERNAL"
    DATABASE = "DATABASE"
    MANAGEMENT = "MANAGEMENT"

class RouteStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNREACHABLE = "UNREACHABLE"
    DEGRADED = "DEGRADED"

class NetworkInterfaceConfig(BaseModel):
    interface_id: str = Field(default="")
    ip_address: str = Field(default="")
    subnet_mask: str = Field(default="255.255.255.0")
    subnet_cidr: Optional[str] = None
    mac_address: Optional[str] = None
    is_up: bool = True

    @model_validator(mode="before")
    @classmethod
    def _compat_interface(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            if "name" in d and "interface_id" not in d:
                d["interface_id"] = d["name"]
            if "interface_id" in d and "name" not in d:
                d["name"] = d["interface_id"]
            return d
        return data

class RouteEntryModel(BaseModel):
    destination: str = Field(default="0.0.0.0/0")
    destination_cidr: Optional[str] = None
    gateway: Optional[str] = None
    gateway_ip: Optional[str] = None
    next_hop: Optional[str] = None
    interface: str = Field(default="eth0")
    interface_id: Optional[str] = None
    metric: int = Field(default=1)

    @model_validator(mode="before")
    @classmethod
    def _compat_route(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            dest = d.get("destination") or d.get("destination_cidr") or "0.0.0.0/0"
            d["destination"] = dest
            d["destination_cidr"] = dest

            gw = d.get("gateway_ip") or d.get("gateway") or d.get("next_hop") or ""
            d["gateway"] = gw
            d["gateway_ip"] = gw
            d["next_hop"] = gw

            iface = d.get("interface") or d.get("interface_id") or "eth0"
            d["interface"] = iface
            d["interface_id"] = iface

            return d
        return data

RouteEntryConfig = RouteEntryModel

class ConfigurationHistoryRecord(BaseModel):
    device_id: str = Field(default="")
    deviceId: Optional[str] = None
    action: str = Field(default="")
    field_changed: str = Field(default="")
    previous_value: Any = None
    new_value: Any = None
    reason: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="before")
    @classmethod
    def _compat_history(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            dev = d.get("device_id") or d.get("deviceId") or ""
            d["device_id"] = dev
            d["deviceId"] = dev
            return d
        return data
class NetworkDeviceModel(BaseModel):
    model_config = {"extra": "allow"}

    id: str = Field(default="")
    name: str = Field(default="")
    hostname: Optional[str] = None
    type: Optional[Any] = None
    device_type: DeviceTypeEnum = Field(default=DeviceTypeEnum.SERVER)
    role: Optional[str] = None
    zone: Optional[Any] = None
    networkZone: NetworkZoneEnum = Field(default=NetworkZoneEnum.INTERNAL)
    ip_addresses: List[str] = Field(default_factory=list)
    ipAddresses: List[str] = Field(default_factory=list)
    macAddresses: List[str] = Field(default_factory=list)
    interfaces: List[NetworkInterfaceConfig] = Field(default_factory=list)
    operatingSystem: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    routes: List[RouteEntryModel] = Field(default_factory=list)
    is_compromised: bool = False
    security_state: str = Field(default="NORMAL")
    securityState: str = Field(default="NORMAL")
    currentState: str = Field(default="NORMAL")
    status: str = Field(default="ONLINE")
    riskScore: float = Field(default=0.0)
    risk_score: float = Field(default=0.0)
    lastUpdated: Optional[str] = None
    last_updated: Optional[str] = None
    createdAt: Optional[str] = None
    created_at: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _compat_device(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            if "name" in d and "hostname" not in d:
                d["hostname"] = d["name"]
            if "hostname" in d and "name" not in d:
                d["name"] = d["hostname"]

            if "type" in d and "device_type" not in d:
                d["device_type"] = d["type"]
            if "device_type" in d and "type" not in d:
                d["type"] = d["device_type"]

            if "zone" in d and "networkZone" not in d:
                d["networkZone"] = d["zone"]
            if "networkZone" in d and "zone" not in d:
                d["zone"] = d["networkZone"]

            if "ip_addresses" in d and "ipAddresses" not in d:
                d["ipAddresses"] = d["ip_addresses"]
            if "ipAddresses" in d and "ip_addresses" not in d:
                d["ip_addresses"] = d["ipAddresses"]

            return d
        return data

    @property
    def primary_ip(self) -> str:
        if self.ipAddresses:
            return self.ipAddresses[0]
        if self.ip_addresses:
            return self.ip_addresses[0]
        return ""

    @property
    def ip(self) -> str:
        return self.primary_ip

    @property
    def deviceId(self) -> str:
        return self.id
class RouteStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNREACHABLE = "UNREACHABLE"
    DEGRADED = "DEGRADED"

class ForwardingDecisionResult(BaseModel):
    model_config = {"extra": "allow"}

    action: str = Field(default="FORWARD")  # FORWARD, DROP, REJECT, LOCAL_DELIVERY
    destination_ip: str = Field(default="")
    next_hop: Optional[str] = None
    interface_id: Optional[str] = None
    matched_route: Optional[Any] = None
    hop_count: int = 0
    traversed_devices: List[str] = Field(default_factory=list)
    path_hops: List[str] = Field(default_factory=list)
    total_latency_ms: float = 0.0
    status: str = Field(default="SUCCESS")
    reason: Optional[str] = None
