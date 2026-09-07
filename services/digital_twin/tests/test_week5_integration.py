import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, 
    NetworkInterfaceConfig, RouteEntryModel
)
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.firewall import (
    FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.devices.device_configuration_engine import config_engine
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.routing_engine import routing_engine
from services.digital_twin.core.topology.switch_engine import switch_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine

def run_week5_master_audit():
    print("================================================================================")
    print("       WEEK 5 FINAL INTEGRATION & PERIMETER SECURITY AUDIT                      ")
    print("================================================================================\n")

    # Clear previous runtime state
    device_registry.clear()
    config_engine.clearHistory()
    connection_registry.clear()
    firewall_engine.clear()

    # 1. Provision Canonical Topology
    print("[1/6] Provisioning Topology: Internet, Firewall, Router, Switch, Web, DB, DNS, Client...")
    fw = NetworkDeviceModel(id="fw-01", hostname="FIREWALL-01", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL)
    rtr = NetworkDeviceModel(id="rtr-01", hostname="ROUTER-01", type=DeviceTypeEnum.ROUTER, ipAddresses=["192.168.1.1"], networkZone=NetworkZoneEnum.INTERNAL)
    sw = NetworkDeviceModel(id="sw-01", hostname="SWITCH-01", type=DeviceTypeEnum.SWITCH, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-SERVER-01", type=DeviceTypeEnum.SERVER, ipAddresses=["192.168.20.10"], ports=[80, 443], networkZone=NetworkZoneEnum.DMZ)
    db = NetworkDeviceModel(id="db-01", hostname="DB-SERVER-01", type=DeviceTypeEnum.DATABASE, ipAddresses=["192.168.20.20"], ports=[5432], networkZone=NetworkZoneEnum.INTERNAL)
    dns = NetworkDeviceModel(id="dns-01", hostname="DNS-SERVER-01", type=DeviceTypeEnum.DNS_SERVER, ipAddresses=["192.168.20.30"], ports=[53], networkZone=NetworkZoneEnum.INTERNAL)
    client = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, ipAddresses=["192.168.30.10"], networkZone=NetworkZoneEnum.INTERNAL)
    inet = NetworkDeviceModel(id="inet-node", hostname="INTERNET-PROBE", type=DeviceTypeEnum.CLIENT, ipAddresses=["8.8.8.8"], networkZone=NetworkZoneEnum.EXTERNAL)

    for d in [fw, rtr, sw, web, db, dns, client, inet]:
        device_registry.createDevice(d)

    assert device_registry.count() == 8
    print("    [PASS] 8 canonical devices registered.")

    # 2. Zone Assignment
    print("\n[2/6] Assigning Devices into Network Security Zones...")
    firewall_engine.assignDeviceToZone("zone-internet", "inet-node")
    firewall_engine.assignDeviceToZone("zone-dmz", "web-01")
    firewall_engine.assignDeviceToZone("zone-database", "db-01")
    firewall_engine.assignDeviceToZone("zone-internal", "client-01")
    firewall_engine.assignDeviceToZone("zone-internal", "dns-01")

    assert firewall_engine.getDeviceZone("inet-node") == NetworkZoneTypeEnum.INTERNET
    assert firewall_engine.getDeviceZone("web-01") == NetworkZoneTypeEnum.DMZ
    assert firewall_engine.getDeviceZone("db-01") == NetworkZoneTypeEnum.DATABASE
    assert firewall_engine.getDeviceZone("client-01") == NetworkZoneTypeEnum.INTERNAL
    print("    [PASS] Device security zones mapped.")

    # 3. Establish Physical/Network Connections
    print("\n[3/6] Wiring Physical and Network Connections...")
    connection_registry.createConnection(NetworkConnectionModel(id="c-fw-rtr", sourceDevice="fw-01", destinationDevice="rtr-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-rtr-sw", sourceDevice="rtr-01", destinationDevice="sw-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-sw-web", sourceDevice="sw-01", destinationDevice="web-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-sw-db", sourceDevice="sw-01", destinationDevice="db-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-sw-dns", sourceDevice="sw-01", destinationDevice="dns-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-sw-client", sourceDevice="sw-01", destinationDevice="client-01", connectionType=ConnectionTypeEnum.PHYSICAL))

    assert connection_registry.count() == 6
    print("    [PASS] 6 topological connections registered.")

    # 4. Inject Firewall Rules
    print("\n[4/6] Injecting Firewall Policy Rules into FirewallEngine...")
    # Rule 1: Internet -> DMZ: ALLOW HTTPS (443)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-001",
        sourceZone=NetworkZoneTypeEnum.INTERNET,
        destinationZone=NetworkZoneTypeEnum.DMZ,
        protocol="TCP",
        destinationPort=443,
        action=FirewallActionEnum.ALLOW,
        priority=10,
        description="Allow HTTPS from Internet to DMZ Web Server"
    ))

    # Rule 2: DMZ -> Database: ALLOW PostgreSQL (5432)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-002",
        sourceZone=NetworkZoneTypeEnum.DMZ,
        destinationZone=NetworkZoneTypeEnum.DATABASE,
        protocol="TCP",
        destinationPort=5432,
        action=FirewallActionEnum.ALLOW,
        priority=20,
        description="Allow DMZ Web Tier to query PostgreSQL database"
    ))

    # Rule 3: Client -> Database: Explicit DENY DIRECT
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-003",
        sourceZone=NetworkZoneTypeEnum.INTERNAL,
        destinationZone=NetworkZoneTypeEnum.DATABASE,
        protocol="TCP",
        destinationPort=5432,
        action=FirewallActionEnum.DENY,
        priority=5,
        description="Deny direct client access to database tier"
    ))

    print(f"    [PASS] {len(firewall_engine.listRules())} firewall policy rules active.")

    # 5. Execute Policy Inspection Scenarios
    print("\n[5/6] Inspecting Network Boundary Policies...")
    
    # Scenario A: Internet -> DMZ (HTTPS 443) -> EXPECT ALLOW
    res_a = firewall_engine.inspectTraffic("inet-node", "web-01", "TCP", 443)
    print(f"    Scenario A (Internet -> Web 443)   : {res_a.decision.value} (Rule: {res_a.matched_rule_id})")
    assert res_a.decision == FirewallActionEnum.ALLOW

    # Scenario B: Internet -> Internal Client (TCP 3389) -> EXPECT DENY (Implicit)
    res_b = firewall_engine.inspectTraffic("inet-node", "client-01", "TCP", 3389)
    print(f"    Scenario B (Internet -> Client 3389): {res_b.decision.value} (Rule: {res_b.matched_rule_id})")
    assert res_b.decision == FirewallActionEnum.DENY

    # Scenario C: DMZ -> Database (PostgreSQL 5432) -> EXPECT ALLOW
    res_c = firewall_engine.inspectTraffic("web-01", "db-01", "TCP", 5432)
    print(f"    Scenario C (DMZ Web -> DB 5432)    : {res_c.decision.value} (Rule: {res_c.matched_rule_id})")
    assert res_c.decision == FirewallActionEnum.ALLOW

    # Scenario D: Internal Client -> Database (PostgreSQL 5432) -> EXPECT DENY
    res_d = firewall_engine.inspectTraffic("client-01", "db-01", "TCP", 5432)
    print(f"    Scenario D (Client -> DB Direct)   : {res_d.decision.value} (Rule: {res_d.matched_rule_id})")
    assert res_d.decision == FirewallActionEnum.DENY
    print("    [PASS] All 4 security policy boundaries strictly enforced.")

    # 6. Switch & Router Subsystem Check
    print("\n[6/6] Verifying Switch & Router Subsystems Integration...")
    switch_engine.connectDeviceToSwitch("sw-01", 1, "client-01", "AA:BB:CC:30:00:10")
    switch_engine.connectDeviceToSwitch("sw-01", 2, "web-01", "AA:BB:CC:20:00:10")
    cam = switch_engine.getMacTable("sw-01")
    assert len(cam) == 2
    print("    [PASS] Layer 2 CAM table learned switch endpoints.")

    routing_engine.addRoute("rtr-01", RouteEntryModel(destination="0.0.0.0/0", nextHop="203.0.113.1", interface="wan0"))
    lpm = routing_engine.findRoute("rtr-01", "8.8.8.8")
    assert lpm.path_resolved is True
    print("    [PASS] Layer 3 Longest-Prefix Match verified.")

    print("\n================================================================================")
    print("       WEEK 5 NETWORK DIGITAL TWIN CORE INTEGRATION AUDIT PASSED                ")
    print("================================================================================")

if __name__ == "__main__":
    run_week5_master_audit()