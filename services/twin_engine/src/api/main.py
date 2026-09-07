from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import json
from typing import Optional, List, Dict, Any

from packages.shared_types.src.security import VulnerabilityEntity, CIAScore, AttackSurfaceExposure
from packages.shared_types.src.events import SecurityEvent
from packages.shared_types.src.device import OperatingSystemProfile, PortEntity, ServiceEntity
from packages.shared_types.src.topology import ConnectionEntity, TopologyValidationResult
from packages.shared_types.src.state import CurrentState, SecurityStateModel, StateTransitionRecord
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

from services.digital_twin.core.devices.network_device_registry import (
    device_registry, DeviceAlreadyExistsError, DeviceNotFoundError
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

    # D001: Workstation 1 (Engineering Client)
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

    twin_engine.add_connection(ConnectionEntity(connection_id="c-d001-d005", source_device="D001", destination_device="D005", connection_type="PHYSICAL_LINK", latency_ms=0.5, bandwidth_mbps=1000.0))
    twin_engine.add_connection(ConnectionEntity(connection_id="c-d002-d005", source_device="D002", destination_device="D005", connection_type="PHYSICAL_LINK", latency_ms=0.2, bandwidth_mbps=10000.0))
    twin_engine.add_connection(ConnectionEntity(connection_id="c-d003-d005", source_device="D003", destination_device="D005", connection_type="PHYSICAL_LINK", latency_ms=0.5, bandwidth_mbps=1000.0))
    twin_engine.add_connection(ConnectionEntity(connection_id="c-d004-d005", source_device="D004", destination_device="D005", connection_type="PHYSICAL_LINK", latency_ms=0.8, bandwidth_mbps=10000.0))

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
def register_new_connection(connection: ConnectionEntity):
    twin_engine.add_connection(connection)
    return {
        "status": "CONNECTION_REGISTERED",
        "connection_id": connection.connection_id,
        "type": connection.connection_type,
        "endpoints": f"{connection.source_device} <-> {connection.destination_device}"
    }

@app.get("/api/v1/twin/devices/{device_id}")
def get_device_twin(device_id: str):
    node = twin_engine.node_registry.get(device_id)
    if not node:
        return {"status": "ERROR", "message": f"Device {device_id} not found."}
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
        return {"status": "ERROR", "message": f"Vulnerability {payload.vuln_id} on node {payload.node_id} not found."}
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
        return {"status": "ERROR", "message": f"Node {payload.node_id} not found."}
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
        return {"status": "ERROR", "message": f"Node {impact.node_id} not found."}
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