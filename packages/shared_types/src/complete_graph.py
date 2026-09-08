from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from packages.shared_types.src.network_device import NetworkDeviceModel
from packages.shared_types.src.topology import NetworkConnectionModel
from packages.shared_types.src.zone_graph import ZoneDefinitionModel
from packages.shared_types.src.service_graph import DetailedServiceDependencyModel
from packages.shared_types.src.firewall import FirewallRuleModel

class CompleteGraphSummary(BaseModel):
    total_devices: int
    total_connections: int
    total_zones: int
    total_dependencies: int
    total_firewall_rules: int
    active_devices_count: int
    compromised_devices_count: int
    average_latency_ms: float

class CompleteDigitalTwinGraphModel(BaseModel):
    graph_id: str = Field(default="DT-CORE-GRAPH-V1")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    summary: CompleteGraphSummary
    devices: List[NetworkDeviceModel]
    connections: List[NetworkConnectionModel]
    zones: List[ZoneDefinitionModel]
    dependencies: List[DetailedServiceDependencyModel]
    firewall_rules: List[FirewallRuleModel]
    metadata: Dict[str, Any] = Field(default_factory=dict)

class NetworkOverviewModel(BaseModel):
    devices: int
    connections: int
    zones: int

class DeviceSummaryItem(BaseModel):
    id: str
    type: str
    zone: Optional[str] = None
    state: str = "ONLINE"

class TopologyStateOverview(BaseModel):
    reachable: bool

class Day42DigitalTwinSnapshot(BaseModel):
    network: NetworkOverviewModel
    devices: List[DeviceSummaryItem]
    topology: TopologyStateOverview