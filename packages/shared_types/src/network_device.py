from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import model_validator, BaseModel, Field, field_validator
import re

class DeviceTypeEnum(str, Enum):
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    FIREWALL = "FIREWALL"
    SERVER = "SERVER"
    CLIENT = "CLIENT"
    DATABASE = "DATABASE"
    DNS_SERVER = "DNS_SERVER"

class NetworkZoneEnum(str, Enum):
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    DMZ = "DMZ"
    RESTRICTED = "RESTRICTED"
    MANAGEMENT = "MANAGEMENT"
    DATABASE = "DATABASE"

class RouteStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DEGRADED = "DEGRADED"

class OperationalStatusEnum(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"
    MAINTENANCE = "MAINTENANCE"
    RUNNING = "RUNNING"
    ACTIVE = "ACTIVE"

class NetworkInterfaceConfig(BaseModel):
    interface_id: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    subnet_cidr: Optional[str] = None
    speed_mbps: Optional[float] = 1000.0

class RouteEntryModel(BaseModel):
    destination: str
    nextHop: str
    interface: str
    metric: int = 1
    status: Optional[RouteStatusEnum] = RouteStatusEnum.ACTIVE

class RouteEntryConfig(BaseModel):
    destination: str = ""
    nextHop: str = ""
    interface: str = "eth0"
    metric: int = 100
    destination_cidr: Optional[str] = None
    gateway_ip: Optional[str] = None
    interface_id: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_route_fields(cls, data):
        if isinstance(data, dict):
            dst = data.get("destination") or data.get("destination_cidr") or "0.0.0.0/0"
            nh = data.get("nextHop") or data.get("gateway_ip") or "0.0.0.0"
            iface = data.get("interface") or data.get("interface_id") or "eth0"
            data["destination"] = dst
            data["destination_cidr"] = dst
            data["nextHop"] = nh
            data["gateway_ip"] = nh
            data["interface"] = iface
            data["interface_id"] = iface
        return data

    @model_validator(mode="after")
    def _sync_route_attrs(self):
        if not self.destination_cidr:
            self.destination_cidr = self.destination
        if not self.gateway_ip:
            self.gateway_ip = self.nextHop
        if not self.interface_id:
            self.interface_id = self.interface
        return self

class ForwardingDecisionResult(BaseModel):
    matched_route: Optional[RouteEntryModel] = None
    egress_interface: Optional[str] = None
    next_hop: Optional[str] = None
    is_direct: bool = False
    path_resolved: bool = True

class ConfigurationHistoryRecord(BaseModel):
    device_id: Optional[str] = None
    component: Optional[str] = "network"
    action: str
    field_changed: Optional[str] = None
    previous_value: Optional[Any] = None
    new_value: Optional[Any] = None
    operator: str = "ADMIN"
    reason: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class NetworkDeviceModel(BaseModel):
    id: str
    name: str
    hostname: str
    device_type: DeviceTypeEnum = DeviceTypeEnum.SERVER
    type: Optional[DeviceTypeEnum] = None
    networkZone: NetworkZoneEnum = NetworkZoneEnum.DMZ
    ipAddresses: List[str] = Field(default_factory=list)
    macAddresses: List[str] = Field(default_factory=list)
    openPorts: List[int] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    connections: List[str] = Field(default_factory=list)
    role: Optional[str] = "SERVER"
    services: List[str] = Field(default_factory=list)
    interfaces: List[NetworkInterfaceConfig] = Field(default_factory=list)
    routes: List[RouteEntryConfig] = Field(default_factory=list)
    security_state: str = "NORMAL"
    currentState: str = "ONLINE"
    state: str = "ONLINE"
    risk_score: float = 0.0
    vulnerabilities: List[str] = Field(default_factory=list)
    isActive: bool = True
    lastUpdated: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Properties to support legacy snake_case/camelCase engine calls (.riskScore, .securityState)
    @property
    def riskScore(self) -> float:
        return self.risk_score

    @riskScore.setter
    def riskScore(self, val: float):
        self.risk_score = float(val)

    @property
    def securityState(self) -> str:
        return self.security_state

    @securityState.setter
    def securityState(self, val: str):
        self.security_state = str(val)

    @field_validator("ipAddresses", mode="before")
    @classmethod
    def _validate_ip_addresses(cls, v):
        if not v:
            return []
        if isinstance(v, str):
            v = [v]
        ipv4_regex = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        for ip in v:
            if not isinstance(ip, str) or not ipv4_regex.match(ip):
                raise ValueError(f"Invalid IP address format: {ip}")
            octets = ip.split(".")
            if any(int(oct) > 255 for oct in octets):
                raise ValueError(f"IP address octet out of range (0-255): {ip}")
        return v

    @field_validator("macAddresses", mode="before")
    @classmethod
    def _validate_mac_addresses(cls, v):
        if not v:
            return []
        if isinstance(v, str):
            v = [v]
        mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
        for mac in v:
            if not isinstance(mac, str) or not mac_regex.match(mac):
                raise ValueError(f"Invalid MAC address format: {mac}")
        return v

    @model_validator(mode="before")
    @classmethod
    def _normalize_device_fields(cls, data):
        if isinstance(data, dict):
            did = data.get("id") or data.get("device_id") or data.get("name")
            if not did or not str(did).strip():
                raise ValueError("Device ID cannot be empty or blank.")
            data["id"] = did

            hname = data.get("hostname") or data.get("name")
            if not hname or not str(hname).strip():
                raise ValueError("Hostname cannot be empty or blank.")
            data["hostname"] = hname

            if "name" not in data or not data["name"]:
                data["name"] = hname

            if "riskScore" in data and "risk_score" not in data:
                data["risk_score"] = data["riskScore"]
            elif "risk_score" in data and "riskScore" not in data:
                data["riskScore"] = data["risk_score"]

            if "securityState" in data and "security_state" not in data:
                data["security_state"] = data["securityState"]
            elif "security_state" in data and "securityState" not in data:
                data["securityState"] = data["security_state"]

            if "type" in data and "device_type" not in data:
                data["device_type"] = data["type"]
            elif "device_type" in data and "type" not in data:
                data["type"] = data["device_type"]

            if "ports" not in data and "openPorts" in data:
                data["ports"] = data["openPorts"]
            elif "openPorts" not in data and "ports" in data:
                data["openPorts"] = data["ports"]
        return data

    @model_validator(mode="after")
    def _sync_device_attrs(self):
        if not self.ports and self.openPorts:
            self.ports = self.openPorts
        elif not self.openPorts and self.ports:
            self.openPorts = self.ports
        
        if not self.type and self.device_type:
            self.type = self.device_type
        elif not self.device_type and self.type:
            self.device_type = self.type

        if not self.currentState and self.state:
            self.currentState = self.state
        elif not self.state and self.currentState:
            self.state = self.currentState
        return self