import sys
from pathlib import Path

# Ensure project root is available to resolver
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import asyncio
import json
from typing import Optional, List, Dict, Any

from packages.shared_types.src.security import VulnerabilityEntity, CIAScore, AttackSurfaceExposure
from packages.shared_types.src.events import SecurityEvent
from packages.shared_types.src.device import OperatingSystemProfile, PortEntity, ServiceEntity
from packages.shared_types.src.topology import (
    NetworkConnectionModel, ConnectionTypeEnum, ConnectionStatusEnum, ProtocolEnum, TopologyValidationResult
)
from packages.shared_types.src.state import CurrentState, SecurityStateModel, StateTransitionRecord
from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, NetworkInterfaceConfig, RouteEntryConfig
)

from services.digital_twin.core.devices.network_device_registry import (
    device_registry, DeviceAlreadyExistsError, DeviceNotFoundError
)
from services.digital_twin.core.devices.device_configuration_engine import config_engine
from services.digital_twin.core.topology.reachability_engine import reachability_engine
from packages.shared_types.src.reachability import ReachabilityEvaluationResult
from services.digital_twin.core.topology.zone_engine import (
    zone_engine, ZoneAlreadyExistsError, ZoneNotFoundError
)
from packages.shared_types.src.zone_graph import (
    ZoneDefinitionModel, ZoneBoundaryLinkModel, ZoneSegmentationGraphModel
)
from services.digital_twin.core.topology.topology_engine_v2 import topology_engine
from packages.shared_types.src.topology import TopologySummarySnapshotModel
from services.digital_twin.core.topology.graph_engine import (
    graph_engine, NodeAlreadyExistsError, NodeNotFoundError,
    EdgeAlreadyExistsError, EdgeNotFoundError
)
from packages.shared_types.src.graph import (
    GraphNodeModel, GraphEdgeModel, GraphNeighborsResult, GraphSnapshotModel
)
from services.digital_twin.core.security.firewall_engine import firewall_engine
from packages.shared_types.src.firewall import (
    FirewallRuleModel, NetworkZoneModel, NetworkZoneTypeEnum, FirewallActionEnum, TrafficInspectionResult
)
from services.digital_twin.simulation.generators.port_anomaly_engine import port_anomaly_engine
from packages.shared_types.src.port_anomaly import (
    PortAnomalyProfile, PortProbeMetric, PortAnomalyRunResult, PortStateMutationConfig
)
from services.digital_twin.simulation.generators.connection_anomaly_engine import connection_anomaly_engine
from packages.shared_types.src.connection_anomaly import (
    ConnectionAnomalyProfile, ConnectionLifecycleStateEnum,
    ConnectionAnomalyPatternEnum, ConnectionAnomalyRunResult
)
from services.digital_twin.simulation.generators.traffic_spike_engine import traffic_spike_engine
from packages.shared_types.src.traffic_spike import (
    TrafficSpikeProfile, SpikePhaseEnum, SpikeTickTelemetry, TrafficSpikeRunResult
)
from services.digital_twin.simulation.generators.abnormal_traffic_engine import abnormal_traffic_engine
from packages.shared_types.src.abnormal_traffic import (
    AnomalyTypeEnum, AnomalySeverityEnum, AnomalyProfile, AbnormalEventModel
)
from services.digital_twin.simulation.generators.day57_baseline_generator import day57_generator
from packages.shared_types.src.baseline_dataset import NormalTrafficSummaryModel, BaselineMetadataModel
from services.digital_twin.simulation.generators.normal_traffic_orchestrator import normal_orchestrator
from packages.shared_types.src.normal_traffic import (
    NormalTrafficScenarioConfig, BaselineSummaryModel, OrchestratorEventEnvelope
)
from services.digital_twin.simulation.generators.ssh_traffic_generator import (
    ssh_orchestrator, SshTargetPortClosedError
)
from packages.shared_types.src.ssh_traffic import (
    SshSessionStateEnum, SshAuthMethodEnum, SshTrafficProfile, SshTransactionEvent
)
from services.digital_twin.simulation.generators.dns_traffic_generator import dns_orchestrator
from packages.shared_types.src.dns_traffic import (
    DnsRecordTypeEnum, DnsResponseCodeEnum, DnsTrafficProfile, DnsTransactionEvent
)
from services.digital_twin.simulation.generators.web_traffic_generator import web_orchestrator
from packages.shared_types.src.web_traffic import (
    WebProtocolEnum, HttpMethodEnum, WebTrafficProfile, HttpTransactionEvent
)
from services.digital_twin.simulation.generators.protocol_generators import protocol_coordinator
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum,
    IcmpMessageTypeEnum, UnifiedTrafficEventModel
)
from services.digital_twin.simulation.engine.reproducible_engine import (
    reproducible_engine, DuplicateSimulationIdError
)
from packages.shared_types.src.reproducible_simulation import (
    SimulationExecutionConfig, ReproducibleSimulationEvent, SimulationRunComparisonResult
)
from services.digital_twin.simulation.engine.simulation_engine import (
    simulation_engine, InvalidSimulationStateTransitionError, ScenarioNotFoundError
)
from packages.shared_types.src.simulation import (
    ScenarioModel, SimulationStateEnum, SimulationEventModel, SimulationStatusSnapshotModel
)
from services.digital_twin.core.state.unified_state_coordinator import (
    unified_state_coordinator, DuplicateEventError, OutOfOrderEventError
)
from packages.shared_types.src.state_integration import (
    UniversalStateEvent, DualSourceDeviceState, StateAuditHistoryEntry
)
from services.digital_twin.core.state.security_state_engine import (
    security_state_engine, InvalidSecurityTransitionError,
    InvalidVulnerabilityTransitionError, VulnerabilityNotFoundError
)
from packages.shared_types.src.security_state import (
    SecurityPostureStatusEnum, VulnerabilityLifecycleStatusEnum,
    DynamicVulnerabilityEntity, DeviceVulnerabilitySummary
)
from services.digital_twin.core.state.port_service_engine import (
    port_service_engine, PortNotFoundError, ServiceNotFoundError, DuplicateServiceError
)
from packages.shared_types.src.port_service_state import (
    TrackedPortModel, TrackedServiceModel, PortStateEnum, ServiceDaemonStateEnum, DevicePortServiceSnapshotModel
)
from services.digital_twin.core.state.network_state_engine import (
    network_state_engine, ConnectionAlreadyExistsError as SessionAlreadyExistsError,
    ConnectionSessionNotFoundError
)
from packages.shared_types.src.network_state import (
    DeviceNetworkMetricsModel, ActiveConnectionSessionModel, SessionStateEnum, DeviceConnectionStatsModel
)
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from packages.shared_types.src.performance import (
    PerformanceMetricSnapshot, PerformanceTelemetryPayload, PerformanceLevelEnum
)
from services.digital_twin.core.state.state_transition_engine import (
    state_transition_engine, InvalidStateTransitionError
)
from packages.shared_types.src.device_state import OperationalTransitionRecord
from services.digital_twin.core.state.state_engine import state_engine
from packages.shared_types.src.device_state import (
    ComprehensiveDeviceStateModel, PerformanceStateModel, NetworkTelemetryStateModel,
    PortStateEntry, ServiceRuntimeEntry, SecurityStateBlockModel, OperationalStatusEnum
)
from services.digital_twin.core.topology.complete_graph_engine import complete_graph_engine
from packages.shared_types.src.complete_graph import CompleteDigitalTwinGraphModel
from services.digital_twin.core.topology.service_graph_engine import service_graph_engine
from packages.shared_types.src.service_graph import (
    DetailedServiceDependencyModel, ImpactPropagationResult
)
from services.digital_twin.core.topology.service_dependency_engine import service_dependency_engine
from packages.shared_types.src.service_dependency import (
    ServiceDependencyModel, ServiceDependencyChainResult, DependencyTypeEnum
)
from services.digital_twin.core.topology.switch_engine import switch_engine
from packages.shared_types.src.switch import (
    SwitchPortModel, MacTableEntryModel, VlanModel, 
    PortStatusEnum, Layer2FrameForwardResult
)
from services.digital_twin.core.topology.routing_engine import routing_engine
from packages.shared_types.src.network_device import RouteEntryModel, ForwardingDecisionResult
from services.digital_twin.core.connections.network_connection_registry import (
    connection_registry, ConnectionAlreadyExistsError, ConnectionNotFoundError
)
from services.twin_engine.src.core.twin_state import (
    twin_engine, DeviceEntity, DeviceInterface, NetworkLinkEntity, 
    SubnetEntity, ArpCacheEntry, FirewallRuleEntity, RouteEntry
)
from services.twin_engine.src.core.risk_engine import risk_engine
from services.twin_engine.src.core.siem_engine import siem_engine
from services.network_simulator.src.generators.traffic_engine import SyntheticTrafficGenerator

app = FastAPI(title="Digital Twin Security Core API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Base Payloads ---
class PacketIngestPayload(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    packet_bytes: int = 64

class CIADegradePayload(BaseModel):
    node_id: str
    dimension: str
    degradation: float

class StateTransitionPayload(BaseModel):
    node_id: str
    new_state: str
    trigger_source: str
    reason: str

class OperationalStatePayload(BaseModel):
    node_id: str
    cpu_usage_pct: float
    memory_usage_pct: float
    packet_rate_pps: float
    byte_rate_bps: float
    status: str = "ONLINE"

class VulnerabilityLifecyclePayload(BaseModel):
    node_id: str
    vuln_id: str
    new_status: str

# --- Day 30 Configuration Payloads ---
class AssignIPPayload(BaseModel):
    ip_address: str
    interface_id: str = "eth0"
    reason: str = "IP assignment"

class PortControlPayload(BaseModel):
    port: int
    reason: str = "Port toggle"

class ServiceControlPayload(BaseModel):
    service: str
    reason: str = "Service toggle"

class ZoneChangePayload(BaseModel):
    zone: NetworkZoneEnum
    reason: str = "Zone migration"

@app.on_event("startup")
def bootstrap_security_grounding():
    lan_subnet = SubnetEntity(
        subnet_id="sub-corp-lan",
        name="Corporate-LAN",
        cidr="192.168.1.0/24",
        network_address="192.168.1.0",
        broadcast_address="192.168.1.255",
        gateway_ip="192.168.1.1",
        usable_hosts_count=254
    )
    twin_engine.register_subnet(lan_subnet)

    # D001: Workstation 1
    pc1 = DeviceEntity(
        id="D001",
        hostname="ws-pc-01",
        type="WORKSTATION",
        role="ENGINEERING_CLIENT",
        os=OperatingSystemProfile(name="Windows", version="11 Enterprise", architecture="x64", kernel_release="10.0.22631", patch_level="2026.07-SEC"),
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.11", mac_address="00:50:56:FE:01:11", subnet="192.168.1.0/24", assigned_via_dhcp=True)],
        open_ports=[],
        detailed_ports=[],
        services=["os-workstation-core"],
        detailed_services=[ServiceEntity(name="windows-defender", version="4.18.24050", protocol="TCP", port=0, status="RUNNING")],
        vulnerabilities=[
            VulnerabilityEntity(
                vuln_id="VULN-D001-01",
                cve_id="CVE-2024-21413",
                name="Outlook Moniker RCE Flaw",
                description="Microsoft Outlook Remote Code Execution Vulnerability",
                severity="CRITICAL",
                cvss_score=9.8,
                affected_service="outlook-client",
                status="OPEN",
                remediation="Apply vendor patch KB5002457"
            )
        ],
        firewall_rules=[FirewallRuleEntity(rule_id="fw-pc1", action="ALLOW", protocol="ANY")],
        criticality=4.0
    )

    # D002: Production Web Server
    server = DeviceEntity(
        id="D002",
        hostname="srv-web-01",
        type="SERVER",
        role="APPLICATION_SERVER",
        os=OperatingSystemProfile(name="Linux", version="Ubuntu 24.04 LTS", architecture="x86_64", kernel_release="6.8.0-31-generic", patch_level="2026.08-STABLE"),
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.10", mac_address="00:50:56:FE:01:10", subnet="192.168.1.0/24")],
        open_ports=[80, 443, 22],
        detailed_ports=[
            PortEntity(port_number=80, protocol="TCP", state="OPEN", bound_service="nginx", is_exposed=True),
            PortEntity(port_number=443, protocol="TCP", state="OPEN", bound_service="nginx", is_exposed=True),
            PortEntity(port_number=22, protocol="TCP", state="OPEN", bound_service="openssh", is_exposed=True)
        ],
        services=["nginx/1.24", "openssh-8.9"],
        detailed_services=[
            ServiceEntity(name="nginx", version="1.24.0", protocol="TCP", port=80, status="RUNNING"),
            ServiceEntity(name="nginx-ssl", version="1.24.0", protocol="TCP", port=443, status="RUNNING"),
            ServiceEntity(name="openssh", version="8.9p1", protocol="TCP", port=22, status="RUNNING", associated_cves=["CVE-2023-38408"])
        ],
        vulnerabilities=[
            VulnerabilityEntity(
                vuln_id="VULN-D002-01",
                cve_id="CVE-2023-38408",
                name="OpenSSH PKCS#11 Forwarding RCE",
                description="OpenSSH PKCS#11 Provider Remote Code Execution",
                severity="CRITICAL",
                cvss_score=9.8,
                affected_service="openssh",
                affected_version="8.9p1",
                port=22,
                status="OPEN",
                remediation="Upgrade OpenSSH to version 9.3p2 or higher"
            )
        ],
        firewall_rules=[
            FirewallRuleEntity(rule_id="r1", action="ALLOW", protocol="TCP", port=80),
            FirewallRuleEntity(rule_id="r2", action="ALLOW", protocol="TCP", port=443),
            FirewallRuleEntity(rule_id="r3", action="ALLOW", protocol="TCP", port=22)
        ],
        criticality=8.5
    )

    # D003: Workstation 2
    pc2 = DeviceEntity(
        id="D003",
        hostname="ws-pc-02",
        type="WORKSTATION",
        role="FINANCE_CLIENT",
        os=OperatingSystemProfile(name="Windows", version="11 Enterprise", architecture="x64", kernel_release="10.0.22631", patch_level="2026.07-SEC"),
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.12", mac_address="00:50:56:FE:01:12", subnet="192.168.1.0/24", assigned_via_dhcp=True)],
        open_ports=[],
        detailed_ports=[],
        services=["os-workstation-core"],
        detailed_services=[ServiceEntity(name="financial-suite-agent", version="3.2.1", protocol="TCP", port=0, status="RUNNING")],
        firewall_rules=[FirewallRuleEntity(rule_id="fw-pc2", action="ALLOW", protocol="ANY")],
        criticality=6.0
    )

    # D004: Gateway Router
    router = DeviceEntity(
        id="D004",
        hostname="rtr-gw-01",
        type="ROUTER",
        role="PERIMETER_GATEWAY",
        os=OperatingSystemProfile(name="Linux", version="Alpine Linux 3.20", architecture="x86_64", kernel_release="6.6.32-hardened", patch_level="2026.08-HARDENED"),
        interfaces=[
            DeviceInterface(interface_id="eth0", ip_address="192.168.1.1", mac_address="00:50:56:FE:01:00", subnet="192.168.1.0/24"),
            DeviceInterface(interface_id="eth1", ip_address="203.0.113.5", mac_address="00:50:56:FE:01:01", subnet="203.0.113.0/30")
        ],
        open_ports=[53, 67, 22],
        detailed_ports=[
            PortEntity(port_number=53, protocol="UDP", state="OPEN", bound_service="dnsmasq", is_exposed=False),
            PortEntity(port_number=67, protocol="UDP", state="OPEN", bound_service="dnsmasq", is_exposed=False),
            PortEntity(port_number=22, protocol="TCP", state="OPEN", bound_service="dropbear", is_exposed=False)
        ],
        services=["dnsmasq", "isc-dhcp", "iptables-nat"],
        detailed_services=[
            ServiceEntity(name="dnsmasq", version="2.90", protocol="UDP", port=53, status="RUNNING"),
            ServiceEntity(name="dropbear", version="2024.84", protocol="TCP", port=22, status="RUNNING", associated_cves=["CVE-2023-48795"])
        ],
        vulnerabilities=[
            VulnerabilityEntity(
                vuln_id="VULN-D004-01",
                cve_id="CVE-2023-48795",
                name="SSH Terrapin Prefix Attack",
                description="SSH Terrapin Prefix Truncation Attack",
                severity="HIGH",
                cvss_score=7.5,
                affected_service="dropbear",
                port=22,
                status="OPEN",
                remediation="Disable chacha20-poly1305 and encrypt-then-mac algorithms"
            )
        ],
        firewall_rules=[
            FirewallRuleEntity(rule_id="fw-rtr-1", action="ALLOW", protocol="TCP", port=443),
            FirewallRuleEntity(rule_id="fw-rtr-2", action="ALLOW", protocol="TCP", port=80),
            FirewallRuleEntity(rule_id="fw-rtr-3", action="ALLOW", protocol="UDP", port=53),
            FirewallRuleEntity(rule_id="fw-rtr-4", action="ALLOW", protocol="UDP", port=67)
        ],
        routing_table=[
            RouteEntry(destination_cidr="192.168.1.0/24", gateway_ip="0.0.0.0", interface_id="eth0"),
            RouteEntry(destination_cidr="0.0.0.0/0", gateway_ip="203.0.113.1", interface_id="eth1")
        ],
        criticality=9.5
    )

    # D005: Switch
    switch_node = DeviceEntity(
        id="D005",
        hostname="sw-core-01",
        type="SWITCH",
        role="CORE_SWITCH",
        os=OperatingSystemProfile(name="NetworkOS", version="SwitchCore v4.2", architecture="arm64", kernel_release="embedded-vlan-fw", patch_level="2026.06-CORE"),
        interfaces=[DeviceInterface(interface_id="vlan1", ip_address="0.0.0.0", mac_address="00:50:56:FE:01:FE", subnet="192.168.1.0/24")],
        open_ports=[],
        detailed_ports=[],
        services=["cam-bridging-engine"],
        detailed_services=[ServiceEntity(name="cam-bridging-engine", version="2.1", protocol="ETHERNET", port=0, status="RUNNING")],
        vulnerabilities=[
            VulnerabilityEntity(
                vuln_id="VULN-D005-01",
                cve_id="CVE-INTERNAL-CAM",
                name="Switch CAM Saturation",
                description="Switch CAM Table Saturation Flaw",
                severity="MEDIUM",
                cvss_score=5.0,
                affected_service="cam-table",
                port=0,
                status="OPEN",
                remediation="Enable 802.1X and Port Security limits"
            )
        ],
        firewall_rules=[FirewallRuleEntity(rule_id="fw-sw-1", action="ALLOW", protocol="ANY")],
        criticality=9.0
    )

    for device in [pc1, server, pc2, router, switch_node]:
        twin_engine.add_or_update_node(device)

    # Bootstrap Day 31 compliant connection instances
    twin_engine.add_connection(NetworkConnectionModel(
        id="c-d001-d005", sourceDevice="D001", destinationDevice="D005", 
        connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.5, bandwidth=1000.0
    ))
    twin_engine.add_connection(NetworkConnectionModel(
        id="c-d002-d005", sourceDevice="D002", destinationDevice="D005", 
        connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.2, bandwidth=10000.0
    ))
    twin_engine.add_connection(NetworkConnectionModel(
        id="c-d003-d005", sourceDevice="D003", destinationDevice="D005", 
        connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.5, bandwidth=1000.0
    ))
    twin_engine.add_connection(NetworkConnectionModel(
        id="c-d004-d005", sourceDevice="D004", destinationDevice="D005", 
        connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.8, bandwidth=10000.0
    ))

# ==================== DAY 61: PORT ANOMALY SIMULATION API ====================

_last_port_anomaly_result: Optional[PortAnomalyRunResult] = None

@app.post("/api/v1/twin/simulation/abnormal/port/run")
def api_run_port_anomaly(profile: PortAnomalyProfile):
    global _last_port_anomaly_result
    result = port_anomaly_engine.runPortAnomalyScenario(profile)
    _last_port_anomaly_result = result
    return {"status": "PORT_ANOMALY_COMPLETED", "result": result.model_dump()}

@app.get("/api/v1/twin/simulation/abnormal/port/last")
def api_get_last_port_anomaly_result():
    if not _last_port_anomaly_result:
        raise HTTPException(status_code=404, detail="No port anomaly scenario has been executed yet.")
    return _last_port_anomaly_result.model_dump()

# ==================== DAY 60: CONNECTION ANOMALY SIMULATION API ====================

_last_connection_anomaly_result: Optional[ConnectionAnomalyRunResult] = None

@app.post("/api/v1/twin/simulation/abnormal/connection/run")
def api_run_connection_anomaly(profile: ConnectionAnomalyProfile, sync_to_twin: bool = True):
    global _last_connection_anomaly_result
    result = connection_anomaly_engine.runAnomalyScenario(profile, sync_to_twin=sync_to_twin)
    _last_connection_anomaly_result = result
    return {"status": "CONNECTION_ANOMALY_COMPLETED", "result": result.model_dump()}

@app.get("/api/v1/twin/simulation/abnormal/connection/last")
def api_get_last_connection_anomaly_result():
    if not _last_connection_anomaly_result:
        raise HTTPException(status_code=404, detail="No connection anomaly scenario has been executed yet.")
    return _last_connection_anomaly_result.model_dump()

# ==================== DAY 59: TRAFFIC SPIKE SIMULATION API ===================="

_last_spike_result: Optional[TrafficSpikeRunResult] = None

@app.post("/api/v1/twin/simulation/abnormal/spike/run")
def api_run_traffic_spike(profile: TrafficSpikeProfile, sync_to_twin: bool = True):
    global _last_spike_result
    result = traffic_spike_engine.runSpikeScenario(profile, sync_to_twin=sync_to_twin)
    _last_spike_result = result
    return {"status": "SPIKE_SCENARIO_COMPLETED", "result": result.model_dump()}

@app.get("/api/v1/twin/simulation/abnormal/spike/last")
def api_get_last_spike_result():
    if not _last_spike_result:
        raise HTTPException(status_code=404, detail="No traffic spike scenario has been executed yet.")
    return _last_spike_result.model_dump()

# ==================== DAY 58: ABNORMAL TRAFFIC SIMULATION API ====================

@app.post("/api/v1/twin/simulation/abnormal/inject")
def api_inject_abnormal_traffic(profile: AnomalyProfile, simulation_id: str = "sim-001"):
    try:
        event, packets = abnormal_traffic_engine.injectAnomaly(profile, simulation_id=simulation_id)
        return {
            "status": "ANOMALY_INJECTED",
            "anomaly_event": event.model_dump(),
            "packets_generated_count": len(packets)
        }
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/simulation/abnormal/events")
def api_list_abnormal_events():
    events = abnormal_traffic_engine.getAbnormalEvents()
    return {"count": len(events), "events": [e.model_dump() for e in events]}

@app.get("/api/v1/twin/simulation/abnormal/raw-traffic")
def api_list_abnormal_raw_traffic(limit: int = 50):
    traffic = abnormal_traffic_engine.getRawTrafficEvents()
    return {"count": len(traffic), "events": [t.model_dump() for t in traffic[-limit:]]}

# ==================== DAY 57: GRAND BASELINE INTEGRATION API ====================

class Day57RunPayload(BaseModel):
    durationSeconds: int = Field(default=60, ge=1, le=86400)
    seed: int = Field(default=12345)

@app.post("/api/v1/twin/simulation/baseline/generate")
def api_generate_day57_baseline(payload: Day57RunPayload):
    summary = day57_generator.generate_baseline(
        duration_seconds=payload.durationSeconds,
        seed=payload.seed
    )
    return {"status": "DAY57_BASELINE_GENERATED", "summary": summary.model_dump()}

@app.get("/api/v1/twin/simulation/baseline/summary")
def api_get_day57_summary():
    summary_path = day57_generator.output_dir / "summary.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="summary.json not found. Run generation first.")
    with open(summary_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/v1/twin/simulation/baseline/metadata")
def api_get_day57_metadata():
    meta_path = day57_generator.output_dir / "metadata.json"
    if not meta_path.exists():
        raise HTTPException(status_code=404, detail="metadata.json not found. Run generation first.")
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/v1/twin/simulation/baseline/events")
def api_get_day57_events(limit: int = 10, offset: int = 0):
    events_path = day57_generator.output_dir / "events.jsonl"
    if not events_path.exists():
        raise HTTPException(status_code=404, detail="events.jsonl not found. Run generation first.")
    
    events = []
    with open(events_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx < offset:
                continue
            if len(events) >= limit:
                break
            stripped = line.strip()
            if stripped:
                events.append(json.loads(stripped))
                
    return {"offset": offset, "limit": limit, "count": len(events), "events": events}

# ==================== DAY 56: NORMAL TRAFFIC ORCHESTRATOR API ====================

@app.post("/api/v1/twin/simulation/orchestrator/normal/run")
def api_run_normal_traffic_scenario(config: NormalTrafficScenarioConfig, sync_to_twin: bool = True):
    baseline = normal_orchestrator.runScenario(config, sync_to_twin=sync_to_twin)
    return {"status": "BASELINE_GENERATED", "summary": baseline.model_dump()}

@app.get("/api/v1/twin/simulation/orchestrator/normal/baseline/{baseline_id}")
def api_get_normal_baseline(baseline_id: str):
    baseline = normal_orchestrator.getBaseline(baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"Baseline dataset '{baseline_id}' not found.")
    return baseline.model_dump()

@app.get("/api/v1/twin/simulation/orchestrator/normal/events")
def api_list_orchestrator_events(limit: Optional[int] = None):
    envelopes = normal_orchestrator.getEnvelopes()
    if limit:
        envelopes = envelopes[-limit:]
    return {"count": len(envelopes), "events": [e.model_dump() for e in envelopes]}

# ==================== DAY 55: SSH TRAFFIC SIMULATION API ====================

class SshSessionRequestPayload(BaseModel):
    sourceDevice: str = "admin-01"
    destinationDevice: str = "server-01"
    username: str = "sysadmin"
    destinationPort: int = 22
    authMethod: SshAuthMethodEnum = SshAuthMethodEnum.PUBLIC_KEY
    shouldFail: bool = False
    simulationId: str = "sim-001"

@app.post("/api/v1/twin/simulation/traffic/ssh/session")
def api_generate_ssh_session(payload: SshSessionRequestPayload):
    try:
        events = ssh_orchestrator.generator.generateSessionSequence(
            source_dev=payload.sourceDevice,
            dest_dev=payload.destinationDevice,
            username=payload.username,
            auth_method=payload.authMethod,
            destination_port=payload.destinationPort,
            should_fail=payload.shouldFail,
            simulation_id=payload.simulationId
        )
        return {"status": "SSH_SESSION_GENERATED", "events_count": len(events), "events": [e.model_dump() for e in events]}
    except (DeviceNotFoundError, SshTargetPortClosedError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/simulation/traffic/ssh/profile-run")
def api_run_ssh_profile(profile: SshTrafficProfile):
    try:
        events = ssh_orchestrator.generateFromProfile(profile)
        return {"status": "SSH_PROFILE_EXECUTED", "count": len(events), "events": [e.model_dump() for e in events]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/simulation/traffic/ssh/events")
def api_list_ssh_events():
    events = ssh_orchestrator.getEvents()
    return {"count": len(events), "events": [e.model_dump() for e in events]}

# ==================== DAY 54: DNS TRAFFIC SIMULATION API ====================

class DnsQueryRequestPayload(BaseModel):
    sourceDevice: str = "client-01"
    dnsServer: str = "dns-01"
    domain: str = "web.internal.test"
    queryType: DnsRecordTypeEnum = DnsRecordTypeEnum.A
    simulationId: str = "sim-001"

@app.post("/api/v1/twin/simulation/traffic/dns/query")
def api_generate_dns_query_pair(payload: DnsQueryRequestPayload):
    q, r = dns_orchestrator.generator.generateQueryPair(
        source_dev=payload.sourceDevice,
        dns_server=payload.dnsServer,
        domain=payload.domain,
        query_type=payload.queryType,
        simulation_id=payload.simulationId
    )
    return {
        "status": "DNS_PAIR_GENERATED",
        "query": q.model_dump(),
        "response": r.model_dump()
    }

@app.post("/api/v1/twin/simulation/traffic/dns/profile-run")
def api_run_dns_profile(profile: DnsTrafficProfile, source_device: str = "client-01"):
    events = dns_orchestrator.generateFromProfile(profile, source_dev=source_device)
    return {"status": "DNS_PROFILE_EXECUTED", "count": len(events), "events": [e.model_dump() for e in events]}

@app.get("/api/v1/twin/simulation/traffic/dns/events")
def api_list_dns_events():
    events = dns_orchestrator.getEvents()
    return {"count": len(events), "events": [e.model_dump() for e in events]}

# ==================== DAY 53: HTTP & HTTPS WEB TRAFFIC SIMULATION API ====================

class WebTransactionRequestPayload(BaseModel):
    sourceDevice: str = "client-01"
    destinationDevice: str = "web-01"
    method: HttpMethodEnum = HttpMethodEnum.GET
    path: str = "/"
    statusCode: int = 200
    simulationId: str = "sim-001"

@app.post("/api/v1/twin/simulation/traffic/web/http")
def api_generate_http_transaction(payload: WebTransactionRequestPayload):
    evt = web_orchestrator.http_gen.generateTransaction(
        source_dev=payload.sourceDevice,
        dest_dev=payload.destinationDevice,
        method=payload.method,
        path=payload.path,
        status_code=payload.statusCode,
        simulation_id=payload.simulationId
    )
    return {"status": "HTTP_TRANSACTION_GENERATED", "event": evt.model_dump()}

@app.post("/api/v1/twin/simulation/traffic/web/https")
def api_generate_https_transaction(payload: WebTransactionRequestPayload):
    evt = web_orchestrator.https_gen.generateTransaction(
        source_dev=payload.sourceDevice,
        dest_dev=payload.destinationDevice,
        method=payload.method,
        path=payload.path,
        status_code=payload.statusCode,
        simulation_id=payload.simulationId
    )
    return {"status": "HTTPS_TRANSACTION_GENERATED", "event": evt.model_dump()}

@app.post("/api/v1/twin/simulation/traffic/web/profile-run")
def api_run_web_profile(profile: WebTrafficProfile, source_device: str = "client-01"):
    evts = web_orchestrator.generateFromProfile(profile, source_dev=source_device)
    return {"status": "PROFILE_EXECUTED", "count": len(evts), "events": [e.model_dump() for e in evts]}

@app.get("/api/v1/twin/simulation/traffic/web/events")
def api_list_web_events():
    evts = web_orchestrator.getEvents()
    return {"count": len(evts), "events": [e.model_dump() for e in evts]}

# ==================== DAY 52: PROTOCOL TRAFFIC GENERATION API ====================

class TcpSimulationPayload(BaseModel):
    sourceDevice: str
    destinationDevice: str
    destinationPort: int = 443
    payloadBytes: int = 1200
    simulationId: str = "sim-001"

class UdpSimulationPayload(BaseModel):
    sourceDevice: str
    destinationDevice: str
    destinationPort: int = 53
    payloadBytes: int = 128
    simulationId: str = "sim-001"

class IcmpSimulationPayload(BaseModel):
    sourceDevice: str
    destinationDevice: str
    simulationId: str = "sim-001"

@app.post("/api/v1/twin/simulation/traffic/tcp")
def api_generate_tcp_traffic(payload: TcpSimulationPayload):
    evts = protocol_coordinator.emitTcpFlow(
        src=payload.sourceDevice,
        dst=payload.destinationDevice,
        dst_port=payload.destinationPort,
        payload_bytes=payload.payloadBytes,
        simulation_id=payload.simulationId
    )
    return {"status": "TCP_FLOW_GENERATED", "events_count": len(evts), "events": [e.model_dump() for e in evts]}

@app.post("/api/v1/twin/simulation/traffic/udp")
def api_generate_udp_traffic(payload: UdpSimulationPayload):
    evt = protocol_coordinator.emitUdpDatagram(
        src=payload.sourceDevice,
        dst=payload.destinationDevice,
        dst_port=payload.destinationPort,
        payload_bytes=payload.payloadBytes,
        simulation_id=payload.simulationId
    )
    return {"status": "UDP_DATAGRAM_GENERATED", "event": evt.model_dump()}

@app.post("/api/v1/twin/simulation/traffic/icmp")
def api_generate_icmp_traffic(payload: IcmpSimulationPayload):
    req, rep = protocol_coordinator.emitIcmpPing(
        src=payload.sourceDevice,
        dst=payload.destinationDevice,
        simulation_id=payload.simulationId
    )
    return {"status": "ICMP_PING_GENERATED", "request": req.model_dump(), "reply": rep.model_dump()}

@app.get("/api/v1/twin/simulation/traffic/events")
def api_list_traffic_events():
    evts = protocol_coordinator.getEvents()
    return {"count": len(evts), "events": [e.model_dump() for e in evts]}

# ==================== DAY 51: REPRODUCIBLE SIMULATION API ====================

class CompareRunsPayload(BaseModel):
    run1_id: str
    run2_id: str

class ExecuteCompletePayload(BaseModel):
    source_device: str = "client-01"
    destination_device: str = "web-01"

@app.post("/api/v1/twin/simulation/reproducible/init", status_code=201)
def api_init_reproducible_sim(config: SimulationExecutionConfig):
    try:
        cfg = reproducible_engine.initializeSimulation(config)
        return {"status": "INITIALIZED", "config": cfg.model_dump()}
    except DuplicateSimulationIdError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/simulation/reproducible/execute-complete")
def api_execute_complete_reproducible_sim(payload: ExecuteCompletePayload):
    try:
        evts = reproducible_engine.runComplete(
            source_dev=payload.source_device, dest_dev=payload.destination_device
        )
        return {"status": "EXECUTION_COMPLETED", "event_count": len(evts)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/simulation/reproducible/events/{run_id}")
def api_get_reproducible_events(run_id: str):
    evts = reproducible_engine.getRunEvents(run_id)
    return {"run_id": run_id, "count": len(evts), "events": [e.model_dump() for e in evts]}

@app.post("/api/v1/twin/simulation/reproducible/compare")
def api_compare_simulation_runs(payload: CompareRunsPayload):
    res = reproducible_engine.compareRuns(payload.run1_id, payload.run2_id)
    return res.model_dump()

# ==================== DAY 50: SIMULATION ENGINE ARCHITECTURE API ====================

class TickRequestPayload(BaseModel):
    seconds: float = Field(default=1.0, ge=0.1, le=3600.0)

@app.post("/api/v1/twin/simulation/create", status_code=201)
def api_create_simulation(scenario: ScenarioModel):
    try:
        created = simulation_engine.createSimulation(scenario)
        return {"status": "SIMULATION_CREATED", "scenario": created.model_dump()}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/simulation/start")
def api_start_simulation():
    try:
        status = simulation_engine.startSimulation()
        return {"status": "SIMULATION_STARTED", "snapshot": status.model_dump()}
    except (ScenarioNotFoundError, InvalidSimulationStateTransitionError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/simulation/pause")
def api_pause_simulation():
    try:
        status = simulation_engine.pauseSimulation()
        return {"status": "SIMULATION_PAUSED", "snapshot": status.model_dump()}
    except InvalidSimulationStateTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/simulation/resume")
def api_resume_simulation():
    try:
        status = simulation_engine.resumeSimulation()
        return {"status": "SIMULATION_RESUMED", "snapshot": status.model_dump()}
    except InvalidSimulationStateTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/simulation/stop")
def api_stop_simulation():
    try:
        status = simulation_engine.stopSimulation()
        return {"status": "SIMULATION_STOPPED", "snapshot": status.model_dump()}
    except InvalidSimulationStateTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/simulation/reset")
def api_reset_simulation():
    simulation_engine.resetSimulation()
    return {"status": "SIMULATION_RESET"}

@app.post("/api/v1/twin/simulation/tick")
def api_tick_simulation(payload: TickRequestPayload):
    evt = simulation_engine.tick(payload.seconds)
    state = simulation_engine.getSimulationState()
    return {
        "status": "TICK_EXECUTED",
        "clock_seconds": state.simCurrentTimeSeconds,
        "event": evt.model_dump() if evt else None,
        "simulation_state": state.state.value
    }

@app.get("/api/v1/twin/simulation/state")
def api_get_simulation_state():
    return simulation_engine.getSimulationState().model_dump()

@app.get("/api/v1/twin/simulation/events")
def api_get_simulation_events(limit: Optional[int] = None):
    evts = simulation_engine.getSimulationEvents(limit=limit)
    return {"count": len(evts), "events": [e.model_dump() for e in evts]}

# ==================== DAY 49: UNIFIED DUAL-SOURCE STATE API ====================

@app.post("/api/v1/twin/state/events/ingest")
def api_ingest_state_event(event: UniversalStateEvent):
    try:
        updated_state = unified_state_coordinator.ingestEvent(event)
        return {"status": "EVENT_INGESTED", "state": updated_state.model_dump()}
    except DuplicateEventError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except OutOfOrderEventError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/state/devices/{device_id}/dual")
def api_get_dual_source_device_state(device_id: str):
    try:
        ds = unified_state_coordinator.getDeviceDualState(device_id)
        return ds.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/state/events/history")
def api_get_state_events_history(device_id: Optional[str] = None):
    try:
        records = unified_state_coordinator.getAuditHistory(device_id)
        return {"count": len(records), "records": [r.model_dump() for r in records]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 48: SECURITY & VULNERABILITY STATE API ====================

class SecurityStatusTransitionPayload(BaseModel):
    new_status: SecurityPostureStatusEnum
    reason: str = "Security posture transition"
    source: str = "ANOMALY_DETECTOR"

class VulnerabilityStatusTransitionPayload(BaseModel):
    new_status: VulnerabilityLifecycleStatusEnum
    reason: str = "Vulnerability lifecycle update"
    source: str = "PATCH_MANAGER"

@app.post("/api/v1/twin/security/{device_id}/status/transition")
def api_transition_security_status(device_id: str, payload: SecurityStatusTransitionPayload):
    try:
        rec = security_state_engine.transitionSecurityStatus(
            device_id=device_id,
            new_status=payload.new_status,
            reason=payload.reason,
            source=payload.source
        )
        return {"status": "POSTURE_UPDATED", "record": rec.model_dump()}
    except (DeviceNotFoundError, InvalidSecurityTransitionError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/security/{device_id}/status")
def api_get_security_status(device_id: str):
    try:
        status = security_state_engine.getSecurityStatus(device_id)
        return {"device_id": device_id, "security_status": status.value}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/security/{device_id}/vulnerabilities", status_code=201)
def api_add_vulnerability(device_id: str, vuln: DynamicVulnerabilityEntity):
    try:
        added = security_state_engine.addVulnerability(device_id, vuln)
        return {"status": "VULNERABILITY_REGISTERED", "vulnerability": added.model_dump()}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/security/{device_id}/vulnerabilities/{vuln_id}/transition")
def api_transition_vulnerability_status(device_id: str, vuln_id: str, payload: VulnerabilityStatusTransitionPayload):
    try:
        rec = security_state_engine.transitionVulnerabilityStatus(
            device_id=device_id,
            vulnerability_id=vuln_id,
            new_status=payload.new_status,
            reason=payload.reason,
            source=payload.source
        )
        return {"status": "VULN_STATUS_UPDATED", "record": rec.model_dump()}
    except (DeviceNotFoundError, VulnerabilityNotFoundError, InvalidVulnerabilityTransitionError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/security/{device_id}/vulnerabilities/summary")
def api_get_vulnerability_summary(device_id: str):
    try:
        summary = security_state_engine.getVulnerabilitySummary(device_id)
        return summary.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/security/{device_id}/history")
def api_get_security_history(device_id: str):
    try:
        history = security_state_engine.getSecurityHistory(device_id)
        return {"device_id": device_id, "count": len(history), "history": [h.model_dump() for h in history]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 47: PORT & SERVICE STATE API ====================

class OpenPortPayload(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    protocol: str = "TCP"
    service: str = "unknown"
    reason: str = "Port opened"

class SetPortStatePayload(BaseModel):
    state: PortStateEnum
    reason: str = "State change"

class SetServiceStatusPayload(BaseModel):
    status: ServiceDaemonStateEnum
    reason: str = "Daemon state update"

@app.post("/api/v1/twin/ports/{device_id}/open")
def api_open_port(device_id: str, payload: OpenPortPayload):
    try:
        p = port_service_engine.openPort(
            device_id=device_id,
            port_number=payload.port,
            protocol=payload.protocol,
            service_name=payload.service,
            reason=payload.reason
        )
        return {"status": "PORT_OPENED", "port": p.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/ports/{device_id}/{port}/close")
def api_close_port(device_id: str, port: int):
    try:
        p = port_service_engine.closePort(device_id, port)
        return {"status": "PORT_CLOSED", "port": p.model_dump()}
    except PortNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/ports/{device_id}/{port}/state")
def api_set_port_state(device_id: str, port: int, payload: SetPortStatePayload):
    try:
        p = port_service_engine.setPortState(device_id, port, payload.state, reason=payload.reason)
        return {"status": "PORT_STATE_UPDATED", "port": p.model_dump()}
    except (PortNotFoundError, DeviceNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/ports/{device_id}")
def api_list_ports(device_id: str):
    try:
        ports = port_service_engine.listPorts(device_id)
        return {"device_id": device_id, "count": len(ports), "ports": [p.model_dump() for p in ports]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/services/{device_id}/register", status_code=201)
def api_register_service(device_id: str, service: TrackedServiceModel):
    try:
        s = port_service_engine.registerService(device_id, service)
        return {"status": "SERVICE_REGISTERED", "service": s.model_dump()}
    except DuplicateServiceError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/services/{device_id}/{service_name}/status")
def api_set_service_status(device_id: str, service_name: str, payload: SetServiceStatusPayload):
    try:
        s = port_service_engine.setServiceStatus(device_id, service_name, payload.status, reason=payload.reason)
        return {"status": "SERVICE_STATUS_UPDATED", "service": s.model_dump()}
    except (ServiceNotFoundError, DeviceNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/services/{device_id}")
def api_list_services(device_id: str):
    try:
        services = port_service_engine.listServices(device_id)
        return {"device_id": device_id, "count": len(services), "services": [s.model_dump() for s in services]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/ports-services/{device_id}/snapshot")
def api_get_port_service_snapshot(device_id: str):
    try:
        snap = port_service_engine.getDeviceSnapshot(device_id)
        return snap.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 46: NETWORK & CONNECTION STATE API ====================

class NetworkMetricIngestPayload(BaseModel):
    networkUtilisation: float = Field(..., ge=0.0, le=100.0)
    bytesSent: int = Field(default=0, ge=0)
    bytesReceived: int = Field(default=0, ge=0)
    packetsSent: int = Field(default=0, ge=0)
    packetsReceived: int = Field(default=0, ge=0)

@app.post("/api/v1/twin/network-state/{device_id}/metrics")
def update_device_network_metrics(device_id: str, payload: NetworkMetricIngestPayload):
    try:
        metrics = network_state_engine.updateNetworkMetrics(
            device_id=device_id,
            network_utilisation=payload.networkUtilisation,
            bytes_sent=payload.bytesSent,
            bytes_received=payload.bytesReceived,
            packets_sent=payload.packetsSent,
            packets_received=payload.packetsReceived
        )
        return {"status": "METRICS_UPDATED", "metrics": metrics.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/network-state/{device_id}/metrics")
def get_device_network_metrics(device_id: str):
    try:
        metrics = network_state_engine.getNetworkMetrics(device_id)
        return metrics.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/network-state/connections", status_code=201)
def create_connection_session(session: ActiveConnectionSessionModel):
    try:
        created = network_state_engine.createConnectionState(session)
        return {"status": "SESSION_CREATED", "session": created.model_dump()}
    except SessionAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/network-state/connections/{session_id}/close")
def close_connection_session(session_id: str):
    try:
        closed = network_state_engine.closeConnection(session_id)
        return {"status": "SESSION_CLOSED", "session": closed.model_dump()}
    except ConnectionSessionNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/network-state/connections/{session_id}/fail")
def fail_connection_session(session_id: str):
    try:
        failed = network_state_engine.failConnection(session_id)
        return {"status": "SESSION_FAILED", "session": failed.model_dump()}
    except ConnectionSessionNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/network-state/devices/{device_id}/connections")
def get_device_connection_sessions(device_id: str):
    try:
        sessions = network_state_engine.getDeviceConnections(device_id)
        return {"device_id": device_id, "count": len(sessions), "sessions": [s.model_dump() for s in sessions]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/network-state/devices/{device_id}/stats")
def get_device_connection_stats(device_id: str):
    try:
        stats = network_state_engine.getConnectionStats(device_id)
        return stats.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 45: PERFORMANCE STATE ENGINE API ====================

class SingleMetricPayload(BaseModel):
    value: float = Field(..., ge=0.0, le=100.0)
    source: str = "TELEMETRY"

@app.post("/api/v1/twin/performance/{device_id}/telemetry")
def ingest_performance_telemetry(device_id: str, payload: PerformanceTelemetryPayload):
    try:
        snapshot = performance_state_engine.recordTelemetry(
            device_id, cpu=payload.cpu, memory=payload.memory, source=payload.source
        )
        return {"status": "INGESTED", "performance": snapshot.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/performance/{device_id}/cpu")
def update_device_cpu_metric(device_id: str, payload: SingleMetricPayload):
    try:
        snapshot = performance_state_engine.updateCpu(device_id, payload.value, source=payload.source)
        return {"status": "CPU_UPDATED", "performance": snapshot.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/performance/{device_id}/memory")
def update_device_memory_metric(device_id: str, payload: SingleMetricPayload):
    try:
        snapshot = performance_state_engine.updateMemory(device_id, payload.value, source=payload.source)
        return {"status": "MEMORY_UPDATED", "performance": snapshot.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/performance/{device_id}/current")
def get_current_performance_snapshot(device_id: str):
    try:
        snapshot = performance_state_engine.getPerformanceState(device_id)
        return snapshot.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/performance/{device_id}/history")
def get_performance_telemetry_history(device_id: str):
    try:
        records = performance_state_engine.getHistory(device_id)
        return {"device_id": device_id, "count": len(records), "history": [r.model_dump() for r in records]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 44: STATE TRANSITION ENGINE API ====================

class TransitionRequestPayload(BaseModel):
    device_id: str
    target_state: OperationalStatusEnum
    reason: str = "State transition requested"
    trigger: str = "OPERATOR"

@app.post("/api/v1/twin/operational/transition")
def transition_device_operational_state(payload: TransitionRequestPayload):
    try:
        rec = state_transition_engine.transitionState(
            device_id=payload.device_id,
            to_state=payload.target_state,
            reason=payload.reason,
            trigger=payload.trigger
        )
        return {"status": "TRANSITIONED", "record": rec.model_dump(by_alias=True)}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e))

@app.get("/api/v1/twin/operational/{device_id}/current")
def get_current_operational_state(device_id: str):
    try:
        curr = state_transition_engine.getCurrentState(device_id)
        return {"device_id": device_id, "operational_state": curr.value}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/operational/{device_id}/can-transition")
def check_can_transition(device_id: str, target_state: OperationalStatusEnum):
    try:
        allowed = state_transition_engine.canTransition(device_id, target_state)
        current = state_transition_engine.getCurrentState(device_id)
        return {
            "device_id": device_id,
            "current_state": current.value,
            "target_state": target_state.value,
            "allowed": allowed
        }
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/operational/{device_id}/history")
def get_device_operational_history(device_id: str):
    try:
        history = state_transition_engine.getStateHistory(device_id)
        return {"device_id": device_id, "count": len(history), "history": [h.model_dump(by_alias=True) for h in history]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 43: DIGITAL TWIN STATE ENGINE API ====================

@app.get("/api/v1/twin/state/devices")
def get_all_device_states():
    states = state_engine.getAllDeviceStates()
    return {"count": len(states), "states": [s.model_dump() for s in states]}

@app.get("/api/v1/twin/state/devices/{device_id}")
def get_device_state(device_id: str):
    try:
        s = state_engine.getDeviceState(device_id)
        if not s:
            raise HTTPException(status_code=404, detail=f"State for device '{device_id}' not initialized.")
        return s.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.put("/api/v1/twin/state/devices/{device_id}")
def update_full_device_state(device_id: str, state: ComprehensiveDeviceStateModel):
    if device_id != state.deviceId:
        raise HTTPException(status_code=400, detail="Path device_id does not match body deviceId.")
    try:
        updated = state_engine.updateDeviceState(state)
        return {"status": "STATE_UPDATED", "state": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/state/devices/{device_id}/performance")
def update_device_performance(device_id: str, perf: PerformanceStateModel, reason: str = "Telemetry ingest"):
    try:
        updated = state_engine.updatePerformanceState(device_id, perf, reason=reason)
        return {"status": "PERFORMANCE_UPDATED", "state": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/state/devices/{device_id}/operational")
def update_device_operational_state(device_id: str, operational_state: OperationalStatusEnum, reason: str = "Operator action"):
    try:
        updated = state_engine.updateOperationalState(device_id, operational_state, reason=reason)
        return {"status": "OPERATIONAL_STATE_UPDATED", "state": updated.model_dump()}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/state/devices/{device_id}/security")
def update_device_security_state(device_id: str, sec: SecurityStateBlockModel, reason: str = "SIEM evaluation"):
    try:
        updated = state_engine.updateSecurityState(device_id, sec, reason=reason)
        return {"status": "SECURITY_STATE_UPDATED", "state": updated.model_dump()}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/state/ledger")
def get_state_transition_ledger(device_id: Optional[str] = None, component: Optional[str] = None):
    records = state_engine.getStateHistory(device_id=device_id, component=component)
    return {"count": len(records), "records": [r.model_dump() for r in records]}

# ==================== DAY 42: PHASE 5 SNAPSHOT API ====================

@app.get("/api/v1/twin/snapshot/phase5")
def get_phase5_snapshot():
    return complete_graph_engine.generateDay42Snapshot()

# ==================== DAY 41: COMPLETE DIGITAL TWIN GRAPH API ====================

@app.get("/api/v1/twin/graph/complete")
def get_complete_digital_twin_graph(graph_id: str = Query(default="DT-PROD-V1")):
    model = complete_graph_engine.getCompleteDigitalTwinGraph(graph_id=graph_id)
    return model.model_dump()

# ==================== DAY 40: SERVICE GRAPH & IMPACT API ====================

class ImpactEvaluationPayload(BaseModel):
    failed_device_id: str
    failed_service_name: str

@app.post("/api/v1/twin/services/graph/dependencies", status_code=201)
def create_detailed_service_dependency(dep: DetailedServiceDependencyModel):
    try:
        created = service_graph_engine.addDependency(dep)
        return {"status": "SERVICE_DEPENDENCY_CREATED", "dependency": created.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/services/graph/dependencies")
def list_detailed_service_dependencies(device_id: Optional[str] = None):
    deps = service_graph_engine.listDependencies(device_id)
    return {"count": len(deps), "dependencies": [d.model_dump() for d in deps]}

@app.post("/api/v1/twin/services/graph/impact")
def evaluate_service_impact(payload: ImpactEvaluationPayload):
    res = service_graph_engine.propagateImpact(payload.failed_device_id, payload.failed_service_name)
    return res.model_dump()

# ==================== DAY 39: REACHABILITY ENGINE API ====================

class ReachabilityCheckPayload(BaseModel):
    source_device_id: str
    destination_device_id: str
    protocol: str = "TCP"
    destination_port: Optional[int] = None

@app.post("/api/v1/twin/reachability/check")
def evaluate_reachability(payload: ReachabilityCheckPayload):
    try:
        res = reachability_engine.isReachable(
            payload.source_device_id, payload.destination_device_id,
            payload.protocol, payload.destination_port
        )
        return res.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/reachability/path")
def get_bfs_path(source_id: str = Query(..., min_length=1), destination_id: str = Query(..., min_length=1)):
    path = reachability_engine.findPath(source_id, destination_id)
    if not path:
        return {"source_id": source_id, "destination_id": destination_id, "path_found": False, "hops": []}
    return {"source_id": source_id, "destination_id": destination_id, "path_found": True, "hop_count": len(path) - 1, "hops": path}

@app.get("/api/v1/twin/reachability/shortest")
def get_dijkstra_shortest_path(source_id: str = Query(..., min_length=1), destination_id: str = Query(..., min_length=1)):
    path, cost = reachability_engine.getShortestPath(source_id, destination_id)
    if not path:
        return {"source_id": source_id, "destination_id": destination_id, "path_found": False, "hops": [], "cost": 0.0}
    return {"source_id": source_id, "destination_id": destination_id, "path_found": True, "hop_count": len(path) - 1, "cost": cost, "hops": path}

# ==================== DAY 38: ZONE SEGMENTATION GRAPH API ====================

@app.post("/api/v1/twin/segmentation/zones", status_code=201)
def create_segmentation_zone(zone: ZoneDefinitionModel):
    try:
        created = zone_engine.createZone(zone)
        return {"status": "ZONE_CREATED", "zone": created.model_dump()}
    except ZoneAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))

@app.get("/api/v1/twin/segmentation/zones")
def list_segmentation_zones():
    zones = zone_engine.listZones()
    return {"count": len(zones), "zones": [z.model_dump() for z in zones]}

@app.get("/api/v1/twin/segmentation/zones/{zone_id}")
def get_segmentation_zone(zone_id: str):
    z = zone_engine.getZone(zone_id)
    if not z:
        raise HTTPException(status_code=404, detail=f"Zone '{zone_id}' not found.")
    return z.model_dump()

@app.delete("/api/v1/twin/segmentation/zones/{zone_id}")
def delete_segmentation_zone(zone_id: str):
    try:
        zone_engine.deleteZone(zone_id)
        return {"status": "ZONE_DELETED", "zone_id": zone_id}
    except ZoneNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/segmentation/zones/{zone_id}/devices/{device_id}")
def assign_device_to_segmentation_zone(zone_id: str, device_id: str):
    try:
        zone = zone_engine.assignDeviceToZone(zone_id, device_id)
        return {"status": "DEVICE_ASSIGNED", "zone": zone.model_dump()}
    except (ZoneNotFoundError, DeviceNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/api/v1/twin/segmentation/zones/{zone_id}/devices/{device_id}")
def remove_device_from_segmentation_zone(zone_id: str, device_id: str):
    try:
        removed = zone_engine.removeDeviceFromZone(zone_id, device_id)
        return {"status": "DEVICE_REMOVED", "success": removed}
    except ZoneNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/segmentation/zones/{zone_id}/connections")
def get_segmentation_zone_connections(zone_id: str):
    try:
        conns = zone_engine.getZoneConnections(zone_id)
        return {"zone_id": zone_id, "connection_count": len(conns), "connections": [c.model_dump() for c in conns]}
    except ZoneNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/segmentation/graph")
def get_zone_segmentation_graph():
    graph_model = zone_engine.buildZoneSegmentationGraph()
    return graph_model.model_dump()

# ==================== DAY 37: TOPOLOGY ENGINE API ====================

@app.get("/api/v1/twin/topology/snapshot/summary")
def get_topology_snapshot_summary():
    snapshot = topology_engine.generateTopologySnapshot()
    return snapshot.model_dump()

@app.get("/api/v1/twin/topology/isolated")
def get_isolated_network_devices():
    isolated = topology_engine.detectIsolatedDevices()
    return {"count": len(isolated), "isolated_devices": isolated}

@app.get("/api/v1/twin/topology/neighbors/{device_id}")
def get_device_topology_neighbors(device_id: str):
    try:
        neighbors = topology_engine.findNeighbors(device_id)
        return neighbors
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 36: GRAPH ENGINE API ====================

@app.post("/api/v1/twin/graph/nodes", status_code=201)
def add_graph_node(node: GraphNodeModel):
    try:
        created = graph_engine.addNode(node)
        return {"status": "NODE_ADDED", "node": created.model_dump()}
    except NodeAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))

@app.get("/api/v1/twin/graph/nodes")
def list_graph_nodes(zone: Optional[str] = None, type: Optional[str] = None):
    nodes = graph_engine.getNodes(zone=zone, node_type=type)
    return {"count": len(nodes), "nodes": [n.model_dump() for n in nodes]}

@app.delete("/api/v1/twin/graph/nodes/{node_id}")
def delete_graph_node(node_id: str):
    try:
        graph_engine.removeNode(node_id)
        return {"status": "NODE_DELETED", "node_id": node_id}
    except NodeNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/graph/edges", status_code=201)
def add_graph_edge(edge: GraphEdgeModel, bidirectional: bool = False):
    try:
        created = graph_engine.addEdge(edge, is_bidirectional=bidirectional)
        return {"status": "EDGE_ADDED", "edge": created.model_dump()}
    except EdgeAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except NodeNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/graph/edges")
def list_graph_edges(status: Optional[str] = None, protocol: Optional[str] = None):
    edges = graph_engine.getEdges(status=status, protocol=protocol)
    return {"count": len(edges), "edges": [e.model_dump() for e in edges]}

@app.delete("/api/v1/twin/graph/edges/{edge_id}")
def delete_graph_edge(edge_id: str):
    try:
        graph_engine.removeEdge(edge_id)
        return {"status": "EDGE_DELETED", "edge_id": edge_id}
    except EdgeNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/graph/neighbors/{node_id}")
def get_graph_neighbors(node_id: str):
    try:
        res = graph_engine.getNeighbors(node_id)
        return res.model_dump()
    except NodeNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/graph/snapshot")
def get_graph_snapshot():
    return graph_engine.getSnapshot().model_dump()

# ==================== DAY 35: FIREWALL & ZONE API ====================

class TrafficInspectionPayload(BaseModel):
    source_device_id: str
    destination_device_id: str
    protocol: str = "TCP"
    destination_port: Optional[int] = None

class DeviceZoneAssignPayload(BaseModel):
    device_id: str

@app.post("/api/v1/twin/firewall/rules", status_code=201)
def add_firewall_rule(rule: FirewallRuleModel):
    try:
        created = firewall_engine.addRule(rule)
        return {"status": "RULE_CREATED", "rule": created.model_dump()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/firewall/rules")
def list_firewall_rules():
    rules = firewall_engine.listRules()
    return {"count": len(rules), "rules": [r.model_dump() for r in rules]}

@app.post("/api/v1/twin/firewall/inspect")
def inspect_firewall_traffic(payload: TrafficInspectionPayload):
    result = firewall_engine.inspectTraffic(
        payload.source_device_id, payload.destination_device_id,
        payload.protocol, payload.destination_port
    )
    return result.model_dump()

@app.post("/api/v1/twin/zones", status_code=201)
def create_network_zone(zone: NetworkZoneModel):
    try:
        created = firewall_engine.createZone(zone)
        return {"status": "ZONE_CREATED", "zone": created.model_dump()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/zones")
def list_network_zones():
    zones = firewall_engine.listZones()
    return {"count": len(zones), "zones": [z.model_dump() for z in zones]}

@app.post("/api/v1/twin/zones/{zone_id}/assign")
def assign_device_zone(zone_id: str, payload: DeviceZoneAssignPayload):
    try:
        zone = firewall_engine.assignDeviceToZone(zone_id, payload.device_id)
        return {"status": "DEVICE_ASSIGNED_TO_ZONE", "zone": zone.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== DAY 34: SERVICE DEPENDENCY API ====================

@app.post("/api/v1/twin/services/dependencies", status_code=201)
def create_service_dependency(dep: ServiceDependencyModel):
    try:
        created = service_dependency_engine.registerDependency(dep)
        return {"status": "DEPENDENCY_REGISTERED", "dependency": created.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/services/dependencies")
def list_service_dependencies(device_id: Optional[str] = None):
    if device_id:
        deps = service_dependency_engine.getDependenciesForDevice(device_id)
    else:
        deps = service_dependency_engine.listAllDependencies()
    return {"count": len(deps), "dependencies": [d.model_dump() for d in deps]}

@app.get("/api/v1/twin/services/dependencies/chain")
def trace_service_dependency_chain(
    source_device_id: str = Query(..., description="Root client or service ID"),
    target_device_id: str = Query(..., description="Target service host ID")
):
    chain = service_dependency_engine.traceDependencyChain(source_device_id, target_device_id)
    return chain.model_dump()

# ==================== DAY 33: SWITCH & LAYER 2 API ====================

class ConnectPortPayload(BaseModel):
    port_number: int
    device_id: str
    mac_address: str

class ProcessFramePayload(BaseModel):
    ingress_port: int
    source_mac: str
    destination_mac: str

class CreateVlanPayload(BaseModel):
    vlan_id: int
    name: str
    subnet: Optional[str] = None

@app.post("/api/v1/twin/switches/{switch_id}/ports/connect")
def connect_switch_port(switch_id: str, payload: ConnectPortPayload):
    try:
        port = switch_engine.connectDeviceToSwitch(
            switch_id, payload.port_number, payload.device_id, payload.mac_address
        )
        return {"status": "PORT_CONNECTED", "port": port.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/switches/{switch_id}/ports/disconnect")
def disconnect_switch_port(switch_id: str, port_number: int = Query(..., ge=1)):
    try:
        port = switch_engine.disconnectDeviceFromSwitch(switch_id, port_number)
        return {"status": "PORT_DISCONNECTED", "port": port.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/switches/{switch_id}/cam")
def get_switch_cam_table(switch_id: str):
    try:
        entries = switch_engine.getMacTable(switch_id)
        return {"switch_id": switch_id, "entries_count": len(entries), "cam_table": [e.model_dump() for e in entries]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/switches/{switch_id}/frame/process")
def process_l2_frame(switch_id: str, payload: ProcessFramePayload):
    try:
        res = switch_engine.processEthernetFrame(
            switch_id, payload.ingress_port, payload.source_mac, payload.destination_mac
        )
        return res.model_dump()
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/switches/{switch_id}/vlans")
def create_switch_vlan(switch_id: str, payload: CreateVlanPayload):
    try:
        vlan = switch_engine.createVlan(switch_id, payload.vlan_id, payload.name, payload.subnet)
        return {"status": "VLAN_CREATED", "vlan": vlan.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== DAY 32: ROUTING & FORWARDING API ====================

class RouteLookupPayload(BaseModel):
    destination_ip: str

@app.post("/api/v1/twin/routing/{router_id}/routes")
def add_router_route(router_id: str, route: RouteEntryModel):
    try:
        created = routing_engine.addRoute(router_id, route)
        return {"status": "ROUTE_ADDED", "route": created.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/routing/{router_id}/routes")
def get_router_routing_table(router_id: str):
    try:
        routes = routing_engine.getRoutingTable(router_id)
        return {"router_id": router_id, "routes_count": len(routes), "routes": [r.model_dump() for r in routes]}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/twin/routing/{router_id}/lookup")
def lookup_route_destination(router_id: str, payload: RouteLookupPayload):
    try:
        decision = routing_engine.findRoute(router_id, payload.destination_ip)
        return decision.model_dump()
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/twin/routing/trace")
def trace_l3_forwarding_path(source_device_id: str = Query(..., description="Origin device ID"), destination_ip: str = Query(..., description="Target IP")):
    trace = routing_engine.traceLayer3Path(source_device_id, destination_ip)
    return {
        "source_device": source_device_id,
        "destination_ip": destination_ip,
        "total_hops": len(trace),
        "hops": trace
    }

# ==================== DAY 31: CONNECTION REGISTRY API ====================

@app.post("/api/v1/twin/registry/connections", status_code=201)
def create_registry_connection(conn: NetworkConnectionModel):
    try:
        created = connection_registry.createConnection(conn)
        return {"status": "CREATED", "connection": created.model_dump()}
    except ConnectionAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/registry/connections/{connection_id}")
def get_registry_connection(connection_id: str):
    c = connection_registry.getConnection(connection_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found.")
    return c.model_dump()

@app.get("/api/v1/twin/registry/connections")
def list_registry_connections(
    device_id: Optional[str] = None,
    type: Optional[ConnectionTypeEnum] = None,
    status: Optional[ConnectionStatusEnum] = None
):
    conns = connection_registry.getAllConnections(device_id=device_id, conn_type=type, status=status)
    return {"count": len(conns), "connections": [c.model_dump() for c in conns]}

@app.put("/api/v1/twin/registry/connections/{connection_id}")
def update_registry_connection(connection_id: str, conn: NetworkConnectionModel):
    if connection_id != conn.id:
        raise HTTPException(status_code=400, detail="Path parameter connection_id does not match body id.")
    try:
        updated = connection_registry.updateConnection(conn)
        return {"status": "UPDATED", "connection": updated.model_dump()}
    except ConnectionNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/api/v1/twin/registry/connections/{connection_id}")
def delete_registry_connection(connection_id: str):
    try:
        connection_registry.deleteConnection(connection_id)
        return {"status": "DELETED", "connection_id": connection_id}
    except ConnectionNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DAY 30: DEVICE CONFIGURATION API ====================

@app.post("/api/v1/twin/configure/{device_id}/interface")
def configure_device_interface(device_id: str, iface: NetworkInterfaceConfig, reason: str = "Interface config"):
    try:
        updated = config_engine.configureInterface(device_id, iface, reason=reason)
        return {"status": "CONFIGURED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/ip/assign")
def assign_device_ip(device_id: str, payload: AssignIPPayload):
    try:
        updated = config_engine.assignIPAddress(device_id, payload.ip_address, payload.interface_id, reason=payload.reason)
        return {"status": "IP_ASSIGNED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/ip/remove")
def remove_device_ip(device_id: str, ip_address: str, reason: str = "IP removal"):
    try:
        updated = config_engine.removeIPAddress(device_id, ip_address, reason=reason)
        return {"status": "IP_REMOVED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/port/open")
def open_device_port(device_id: str, payload: PortControlPayload):
    try:
        updated = config_engine.openPort(device_id, payload.port, reason=payload.reason)
        return {"status": "PORT_OPENED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/port/close")
def close_device_port(device_id: str, payload: PortControlPayload):
    try:
        updated = config_engine.closePort(device_id, payload.port, reason=payload.reason)
        return {"status": "PORT_CLOSED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/service/add")
def add_device_service(device_id: str, payload: ServiceControlPayload):
    try:
        updated = config_engine.addService(device_id, payload.service, reason=payload.reason)
        return {"status": "SERVICE_ADDED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/service/remove")
def remove_device_service(device_id: str, payload: ServiceControlPayload):
    try:
        updated = config_engine.removeService(device_id, payload.service, reason=payload.reason)
        return {"status": "SERVICE_REMOVED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/zone")
def change_device_zone(device_id: str, payload: ZoneChangePayload):
    try:
        updated = config_engine.changeZone(device_id, payload.zone, reason=payload.reason)
        return {"status": "ZONE_CHANGED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/twin/configure/{device_id}/route")
def add_device_route(device_id: str, route: RouteEntryConfig, reason: str = "Add static route"):
    try:
        updated = config_engine.addRoute(device_id, route, reason=reason)
        return {"status": "ROUTE_ADDED", "device": updated.model_dump()}
    except (DeviceNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/twin/configure/history")
def get_configuration_history(device_id: Optional[str] = None):
    history = config_engine.getConfigurationHistory(device_id)
    return {"count": len(history), "history": [h.model_dump() for h in history]}

# ==================== DAY 29: DEVICE REGISTRY API ====================

@app.post("/api/v1/twin/registry/devices", status_code=201)
def create_registry_device(device: NetworkDeviceModel):
    try:
        created = device_registry.createDevice(device)
        return {"status": "CREATED", "device": created.model_dump()}
    except DeviceAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))

@app.get("/api/v1/twin/registry/devices/{device_id}")
def get_registry_device(device_id: str):
    dev = device_registry.getDevice(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")
    return dev.model_dump()

@app.get("/api/v1/twin/registry/devices")
def list_registry_devices(zone: Optional[NetworkZoneEnum] = None, type: Optional[DeviceTypeEnum] = None):
    devices = device_registry.getAllDevices(zone=zone, device_type=type)
    return {"count": len(devices), "devices": [d.model_dump() for d in devices]}

@app.put("/api/v1/twin/registry/devices/{device_id}")
def update_registry_device(device_id: str, device: NetworkDeviceModel):
    if device_id != device.id:
        raise HTTPException(status_code=400, detail="Path parameter device_id does not match body id.")
    try:
        updated = device_registry.updateDevice(device)
        return {"status": "UPDATED", "device": updated.model_dump()}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/api/v1/twin/registry/devices/{device_id}")
def delete_registry_device(device_id: str):
    try:
        device_registry.deleteDevice(device_id)
        return {"status": "DELETED", "device_id": device_id}
    except DeviceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ==================== DIGITAL TWIN CORE ROUTES ====================

@app.get("/api/v1/twin/topology")
def get_twin_topology():
    return twin_engine.serialize_twin()

@app.get("/api/v1/twin/topology/path")
def calculate_topology_path(source_id: str = Query(..., description="Origin device ID"), target_id: str = Query(..., description="Target device ID")):
    return twin_engine.find_path(source_id, target_id)

@app.get("/api/v1/twin/topology/dependencies")
def get_topology_dependencies():
    bridges = twin_engine.find_critical_bridges()
    return {
        "critical_articulation_points": [
            {
                "node_id": b_id,
                "hostname": twin_engine.node_registry[b_id].hostname,
                "role": twin_engine.node_registry[b_id].role,
                "impact": "Network partition if compromised or offline"
            }
            for b_id in bridges if b_id in twin_engine.node_registry
        ]
    }

@app.post("/api/v1/twin/topology/connections")
def register_new_connection(connection: NetworkConnectionModel):
    twin_engine.add_connection(connection)
    return {
        "status": "CONNECTION_REGISTERED",
        "connection_id": connection.id,
        "type": connection.connectionType.value,
        "endpoints": f"{connection.sourceDevice} <-> {connection.destinationDevice}"
    }

@app.get("/api/v1/twin/devices/{device_id}")
def get_device_twin(device_id: str):
    node = twin_engine.node_registry.get(device_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")
    return node.model_dump()

@app.get("/api/v1/twin/attack-surface")
def get_network_attack_surface():
    surfaces = []
    for node in twin_engine.node_registry.values():
        surfaces.append({
            "device_id": node.id,
            "hostname": node.hostname,
            "role": node.role,
            "attack_surface": node.attack_surface.model_dump(),
            "open_vulnerabilities": [v.model_dump() for v in node.vulnerabilities if v.status == "OPEN"]
        })
    return {"device_count": len(surfaces), "attack_surfaces": surfaces}

@app.post("/api/v1/twin/vulnerabilities/lifecycle")
def update_vulnerability_lifecycle(payload: VulnerabilityLifecyclePayload):
    success = twin_engine.update_vulnerability_status(payload.node_id, payload.vuln_id, payload.new_status)
    if not success:
        raise HTTPException(status_code=404, detail=f"Vulnerability {payload.vuln_id} on node {payload.node_id} not found.")
    risk = risk_engine.calculate_node_risk(twin_engine.node_registry[payload.node_id])
    return {
        "status": "VULNERABILITY_STATE_UPDATED",
        "node_id": payload.node_id,
        "vuln_id": payload.vuln_id,
        "new_status": payload.new_status,
        "updated_risk_score": risk["composite_risk_score"],
        "risk_severity": risk["risk_severity"]
    }

@app.post("/api/v1/twin/state/transition")
def trigger_state_transition(payload: StateTransitionPayload):
    record = twin_engine.transition_security_state(
        node_id=payload.node_id,
        new_state=payload.new_state,
        trigger_source=payload.trigger_source,
        reason=payload.reason
    )
    if not record:
        return {"status": "NOOP", "message": f"Node {payload.node_id} already in state {payload.new_state} or not found."}
    return {"status": "TRANSITION_COMPLETED", "record": record.model_dump()}

@app.post("/api/v1/twin/state/operational")
def update_operational_health(payload: OperationalStatePayload):
    current = twin_engine.update_current_operational_state(
        node_id=payload.node_id,
        cpu_pct=payload.cpu_usage_pct,
        mem_pct=payload.memory_usage_pct,
        pps=payload.packet_rate_pps,
        bps=payload.byte_rate_bps,
        status=payload.status
    )
    if not current:
        raise HTTPException(status_code=404, detail=f"Node {payload.node_id} not found.")
    return {"status": "HEALTH_UPDATED", "node_id": payload.node_id, "current_state": current.model_dump()}

@app.get("/api/v1/twin/state/history")
def get_state_history(device_id: Optional[str] = None):
    history = twin_engine.state_history
    if device_id:
        history = [h for h in history if h.device_id == device_id]
    return {
        "records_count": len(history),
        "history": [h.model_dump() for h in history]
    }

@app.get("/api/v1/twin/risk")
def get_topology_risk_evaluation(threat_prob: float = 0.2):
    return {
        "timestamp": twin_engine.serialize_twin()["timestamp"],
        "ambient_threat_probability": threat_prob,
        "assessments": risk_engine.evaluate_entire_topology(ambient_threat_prob=threat_prob)
    }

@app.post("/api/v1/siem/events")
def ingest_siem_event(event: SecurityEvent):
    return siem_engine.ingest_security_event(event)

@app.get("/api/v1/siem/incidents")
def get_siem_incidents():
    return {
        "incidents_count": len(siem_engine.active_incidents),
        "incidents": siem_engine.active_incidents,
        "total_events_stored": len(siem_engine.event_store)
    }

@app.get("/api/v1/siem/mitre")
def get_mitre_attack_coverage():
    return {
        "mappings_count": len(siem_engine.attack_mappings),
        "techniques_detected": siem_engine.attack_mappings
    }

@app.post("/api/v1/twin/impact/degrade")
def degrade_node_cia(impact: CIADegradePayload):
    success = twin_engine.degrade_cia(impact.node_id, impact.dimension, impact.degradation)
    if not success:
        raise HTTPException(status_code=404, detail=f"Node {impact.node_id} not found.")
    node = twin_engine.node_registry[impact.node_id]
    return {
        "status": "IMPACT_APPLIED",
        "node_id": node.id,
        "cia_score": node.cia_score.model_dump(),
        "security_state": node.security_state
    }

@app.websocket("/ws/telemetry")
async def websocket_telemetry_stream(websocket: WebSocket):
    await websocket.accept()
    generator = SyntheticTrafficGenerator()
    try:
        while True:
            scenario = "PORT_SCAN" if asyncio.get_event_loop().time() % 10 < 3 else "BENIGN"
            telemetry = generator.generate_flow_telemetry(scenario=scenario)
            
            payload = {
                "type": "TELEMETRY_FLOW",
                "data": telemetry,
                "twin_state": twin_engine.serialize_twin(),
                "risk_profile": risk_engine.evaluate_entire_topology(),
                "soc_incidents": siem_engine.active_incidents
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass