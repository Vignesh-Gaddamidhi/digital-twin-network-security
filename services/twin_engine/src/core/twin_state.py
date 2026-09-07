from typing import Dict, List, Optional, Any, Set
from pydantic import BaseModel, Field
import networkx as nx
from datetime import datetime, timezone

from packages.shared_types.src.security import CIAScore, VulnerabilityEntity, AttackSurfaceExposure
from packages.shared_types.src.device import OperatingSystemProfile, PortEntity, ServiceEntity
from packages.shared_types.src.topology import ConnectionEntity, TopologyValidationResult
from packages.shared_types.src.state import CurrentState, SecurityStateModel, StateTransitionRecord

class FirewallRuleEntity(BaseModel):
    rule_id: str
    action: str          # ALLOW, DROP
    protocol: str        # TCP, UDP, ANY
    port: Optional[int] = None
    cidr_source: Optional[str] = None

class NatMappingEntity(BaseModel):
    internal_ip: str
    internal_port: int
    public_ip: str
    translated_port: int
    protocol: str
    last_active: str

class RouteEntry(BaseModel):
    destination_cidr: str
    gateway_ip: str
    interface_id: str
    metric: int = 100

class ActiveSocketSession(BaseModel):
    session_id: str
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str

class SubnetEntity(BaseModel):
    subnet_id: str
    name: str
    cidr: str
    network_address: str
    broadcast_address: str
    gateway_ip: str
    usable_hosts_count: int

class DeviceInterface(BaseModel):
    interface_id: str
    ip_address: str
    mac_address: str
    subnet: str
    assigned_via_dhcp: bool = False

class ArpCacheEntry(BaseModel):
    ip_address: str
    mac_address: str
    interface_id: str
    is_static: bool = False

class DeviceEntity(BaseModel):
    id: str
    hostname: str
    type: str
    role: str = "NODE"
    interfaces: List[DeviceInterface]
    open_ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    detailed_ports: List[PortEntity] = Field(default_factory=list)
    detailed_services: List[ServiceEntity] = Field(default_factory=list)
    os: OperatingSystemProfile = Field(default_factory=OperatingSystemProfile)
    vulnerabilities: List[VulnerabilityEntity] = Field(default_factory=list)
    arp_cache: List[ArpCacheEntry] = Field(default_factory=list)
    active_sockets: List[ActiveSocketSession] = Field(default_factory=list)
    firewall_rules: List[FirewallRuleEntity] = Field(default_factory=list)
    routing_table: List[RouteEntry] = Field(default_factory=list)
    nat_table: List[NatMappingEntity] = Field(default_factory=list)
    cia_score: CIAScore = Field(default_factory=CIAScore)
    
    # State Models
    current_state: CurrentState = Field(default_factory=CurrentState)
    security_state_model: SecurityStateModel = Field(default_factory=SecurityStateModel)
    
    # Day 26 Attack Surface Model
    attack_surface: AttackSurfaceExposure = Field(default_factory=AttackSurfaceExposure)
    
    status: str = "ONLINE"
    security_state: str = "HEALTHY"
    criticality: float = 5.0
    compromise_probability: float = 0.0

class NetworkLinkEntity(BaseModel):
    link_id: str
    source: str
    target: str
    latency_ms: float = 1.0
    bandwidth_mbps: float = 1000.0
    relationship: str = "PHYSICAL_LINK"

class DigitalTwinGraphManager:
    def __init__(self):
        self.topology: nx.MultiDiGraph = nx.MultiDiGraph()
        self.node_registry: Dict[str, DeviceEntity] = {}
        self.subnets: Dict[str, SubnetEntity] = {}
        self.connections: Dict[str, ConnectionEntity] = {}
        self.state_history: List[StateTransitionRecord] = []

    def register_subnet(self, subnet: SubnetEntity) -> None:
        self.subnets[subnet.subnet_id] = subnet

    def calculate_attack_surface(self, node: DeviceEntity) -> AttackSurfaceExposure:
        """Dynamically computes attack surface metrics and exposure multipliers."""
        open_vulns = sum(1 for v in node.vulnerabilities if v.status == "OPEN")
        open_ports_count = len(node.detailed_ports) if node.detailed_ports else len(node.open_ports)
        
        has_public_wan = any(
            not i.ip_address.startswith(("192.168.", "10.", "172.16.", "127.", "0.0.0.0"))
            for i in node.interfaces
        )

        if has_public_wan or node.type in ("ROUTER", "FIREWALL"):
            tier = "EXTERNAL"
            accessibility = "REACHABLE"
            mult = 1.0
        elif node.type == "SERVER" and any(p in (80, 443) for p in node.open_ports):
            tier = "DMZ"
            accessibility = "REACHABLE"
            mult = 0.8
        elif node.type == "SWITCH":
            tier = "INTERNAL"
            accessibility = "RESTRICTED"
            mult = 0.3
        else:
            tier = "INTERNAL"
            accessibility = "RESTRICTED"
            mult = 0.2

        return AttackSurfaceExposure(
            exposure_tier=tier,
            accessibility=accessibility,
            is_publicly_routable=has_public_wan,
            ingress_port_count=open_ports_count,
            open_vulnerability_count=open_vulns,
            exposure_multiplier=mult
        )

    def add_or_update_node(self, node: DeviceEntity) -> None:
        node.attack_surface = self.calculate_attack_surface(node)
        self.node_registry[node.id] = node
        self.topology.add_node(
            node.id,
            hostname=node.hostname,
            device_type=node.type,
            role=node.role,
            status=node.current_state.status,
            security_state=node.security_state_model.security_status,
            exposure_tier=node.attack_surface.exposure_tier,
            criticality=node.criticality,
            compromise_probability=node.compromise_probability,
            cia_confidentiality=node.cia_score.confidentiality,
            cia_integrity=node.cia_score.integrity,
            cia_availability=node.cia_score.availability
        )

    def update_vulnerability_status(self, node_id: str, vuln_id: str, new_status: str) -> bool:
        """Updates vulnerability lifecycle state (OPEN, MITIGATED, PATCHED)."""
        node = self.node_registry.get(node_id)
        if not node:
            return False
        
        found = False
        for v in node.vulnerabilities:
            if v.vuln_id == vuln_id or v.cve_id == vuln_id:
                v.status = new_status
                found = True
                break

        if found:
            self.add_or_update_node(node)
            return True
        return False

    def transition_security_state(self, node_id: str, new_state: str, trigger_source: str, reason: str) -> Optional[StateTransitionRecord]:
        node = self.node_registry.get(node_id)
        if not node:
            return None

        prev_state = node.security_state_model.security_status
        if prev_state == new_state:
            return None

        record = StateTransitionRecord(
            device_id=node_id,
            previous_state=prev_state,
            new_state=new_state,
            trigger_source=trigger_source,
            reason=reason,
            risk_score=node.security_state_model.risk_score
        )
        self.state_history.append(record)

        node.security_state_model.security_status = new_state
        node.security_state_model.last_security_event = trigger_source
        node.security_state_model.last_evaluated = datetime.now(timezone.utc).isoformat()
        
        node.security_state = "COMPROMISED" if new_state == "COMPROMISED" else "SUSPICIOUS" if new_state in ("SUSPICIOUS", "AT_RISK") else "HEALTHY"
        self.add_or_update_node(node)
        return record

    def update_current_operational_state(self, node_id: str, cpu_pct: float, mem_pct: float, pps: float, bps: float, status: str = "ONLINE"):
        node = self.node_registry.get(node_id)
        if not node:
            return None
        node.current_state.cpu_usage_pct = cpu_pct
        node.current_state.memory_usage_pct = mem_pct
        node.current_state.network_state.packet_rate_pps = pps
        node.current_state.network_state.byte_rate_bps = bps
        node.current_state.status = status
        node.status = status
        node.current_state.last_updated = datetime.now(timezone.utc).isoformat()
        self.add_or_update_node(node)
        return node.current_state

    def add_connection(self, conn: Any) -> None:
        c_id = getattr(conn, "id", getattr(conn, "connection_id", "conn-unknown"))
        src = getattr(conn, "sourceDevice", getattr(conn, "source_device", None))
        dst = getattr(conn, "destinationDevice", getattr(conn, "destination_device", None))
        c_type = getattr(conn, "connectionType", getattr(conn, "connection_type", "PHYSICAL"))
        if hasattr(c_type, "value"):
            c_type = c_type.value
        proto = getattr(conn, "protocol", "TCP")
        if hasattr(proto, "value"):
            proto = proto.value
        status = getattr(conn, "status", "ACTIVE")
        if hasattr(status, "value"):
            status = status.value
        latency = getattr(conn, "latency", getattr(conn, "latency_ms", 1.0))
        bandwidth = getattr(conn, "bandwidth", getattr(conn, "bandwidth_mbps", 1000.0))

        self.connections[c_id] = conn
        self.topology.add_edge(
            src, dst,
            key=c_id,
            connection_type=c_type,
            protocol=proto,
            status=status,
            latency_ms=latency,
            bandwidth_mbps=bandwidth
        )
        if c_type in ("PHYSICAL", "PHYSICAL_LINK"):
            self.topology.add_edge(
                dst, src,
                key=f"{c_id}-rev",
                connection_type=c_type,
                protocol=proto,
                status=status,
                latency_ms=latency,
                bandwidth_mbps=bandwidth
            )

    def add_link(self, link: NetworkLinkEntity) -> None:
        conn = ConnectionEntity(
            connection_id=link.link_id,
            source_device=link.source,
            destination_device=link.target,
            connection_type=link.relationship,
            latency_ms=link.latency_ms,
            bandwidth_mbps=link.bandwidth_mbps
        )
        self.add_connection(conn)

    def find_path(self, source_id: str, target_id: str) -> TopologyValidationResult:
        if source_id not in self.node_registry or target_id not in self.node_registry:
            return TopologyValidationResult(is_connected=False)

        undirected_view = self.topology.to_undirected()
        try:
            path = nx.shortest_path(undirected_view, source=source_id, target=target_id)
            total_latency = 0.0
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                edge_data = undirected_view.get_edge_data(u, v)
                min_lat = min(e.get("latency_ms", 1.0) for e in edge_data.values())
                total_latency += min_lat

            return TopologyValidationResult(
                is_connected=True,
                path_hops=path,
                hop_count=len(path) - 1,
                total_latency_ms=round(total_latency, 2),
                traversed_devices=[self.node_registry[p].hostname for p in path]
            )
        except nx.NetworkXNoPath:
            return TopologyValidationResult(is_connected=False)

    def get_reachable_devices(self, source_id: str) -> List[Dict[str, Any]]:
        if source_id not in self.node_registry:
            return []
        undirected_view = self.topology.to_undirected()
        reachable_ids = nx.node_connected_component(undirected_view, source_id)
        results = []
        for dev_id in reachable_ids:
            if dev_id != source_id:
                dev = self.node_registry[dev_id]
                results.append({
                    "id": dev.id,
                    "hostname": dev.hostname,
                    "type": dev.type,
                    "role": dev.role,
                    "exposure_tier": dev.attack_surface.exposure_tier,
                    "security_state": dev.security_state_model.security_status
                })
        return results

    def find_critical_bridges(self) -> List[str]:
        undirected_view = nx.Graph(self.topology.to_undirected())
        return list(nx.articulation_points(undirected_view))

    def degrade_cia(self, node_id: str, dimension: str, degradation: float) -> bool:
        node = self.node_registry.get(node_id)
        if not node:
            return False

        if dimension == "CONFIDENTIALITY":
            node.cia_score.confidentiality = max(0.0, node.cia_score.confidentiality - degradation)
        elif dimension == "INTEGRITY":
            node.cia_score.integrity = max(0.0, node.cia_score.integrity - degradation)
        elif dimension == "AVAILABILITY":
            node.cia_score.availability = max(0.0, node.cia_score.availability - degradation)

        min_cia = min(node.cia_score.confidentiality, node.cia_score.integrity, node.cia_score.availability)
        if min_cia < 0.3:
            self.transition_security_state(node_id, "COMPROMISED", "CIA_ENGINE", f"Critical {dimension} collapse (score < 0.3)")
        elif min_cia < 0.7:
            self.transition_security_state(node_id, "SUSPICIOUS", "CIA_ENGINE", f"{dimension} degradation observed")

        self.add_or_update_node(node)
        return True

    def serialize_twin(self) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subnets": [subnet.model_dump() for subnet in self.subnets.values()],
            "devices": [node.model_dump() for node in self.node_registry.values()],
            "connections": [c.model_dump() for c in self.connections.values()],
            "critical_articulation_points": self.find_critical_bridges(),
            "state_history_count": len(self.state_history)
        }

twin_engine = DigitalTwinGraphManager()