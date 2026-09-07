from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from packages.shared_types.src.security import VulnerabilityEntity, CIAScore

class OperatingSystemProfile(BaseModel):
    name: str = "Linux"
    version: str = "Ubuntu 24.04 LTS"
    architecture: str = "x86_64"
    kernel_release: str = "6.8.0-generic"
    patch_level: str = "2026.08-STABLE"

class PortEntity(BaseModel):
    port_number: int = Field(ge=1, le=65535)
    protocol: str = "TCP" # TCP, UDP
    state: str = "OPEN"   # OPEN, FILTERED, CLOSED
    bound_service: str
    is_exposed: bool = False

class ServiceEntity(BaseModel):
    name: str
    version: str
    protocol: str = "TCP"
    port: int
    status: str = "RUNNING" # RUNNING, STOPPED, DEGRADED
    process_id: Optional[int] = None
    associated_cves: List[str] = Field(default_factory=list)

class DeviceInterfaceEntity(BaseModel):
    interface_id: str
    ip_address: str
    mac_address: str
    subnet_cidr: str
    assigned_via_dhcp: bool = False
    is_up: bool = True

class DeviceTwinModel(BaseModel):
    id: str
    hostname: str
    type: str # WORKSTATION, SERVER, ROUTER, SWITCH, FIREWALL
    role: str # APPLICATION_SERVER, CLIENT, GATEWAY, ACCESS_SWITCH
    criticality: float = Field(default=5.0, ge=1.0, le=10.0)
    os: OperatingSystemProfile = Field(default_factory=OperatingSystemProfile)
    interfaces: List[DeviceInterfaceEntity]
    ports: List[PortEntity] = Field(default_factory=list)
    services: List[ServiceEntity] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityEntity] = Field(default_factory=list)
    cia_score: CIAScore = Field(default_factory=CIAScore)
    operational_state: str = "ONLINE" # ONLINE, DEGRADED, OFFLINE
    security_state: str = "HEALTHY"   # HEALTHY, SUSPICIOUS, COMPROMISED, ISOLATED
    metadata: Dict[str, Any] = Field(default_factory=dict)