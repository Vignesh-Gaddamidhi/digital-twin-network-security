import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, NetworkInterfaceConfig
)
from packages.shared_types.src.topology import (
    NetworkConnectionModel, ConnectionTypeEnum, ConnectionStatusEnum, ProtocolEnum
)
from packages.shared_types.src.service_graph import (
    DetailedServiceDependencyModel, ServiceCriticalityEnum
)
from packages.shared_types.src.firewall import (
    FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum
)
from packages.shared_types.src.graph import GraphNodeModel, GraphEdgeModel

from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError, DeviceAlreadyExistsError
from services.digital_twin.core.connections.network_connection_registry import connection_registry, ConnectionNotFoundError, ConnectionAlreadyExistsError
from services.digital_twin.core.topology.zone_engine import zone_engine, ZoneNotFoundError, ZoneAlreadyExistsError
from services.digital_twin.core.topology.service_graph_engine import service_graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.topology.reachability_engine import reachability_engine
from services.digital_twin.core.topology.complete_graph_engine import complete_graph_engine

def run_day42_master_integration():
    print("=" * 80)
    print("      PHASE 5 - DAY 42: COMPLETE NETWORK DIGITAL TWIN INTEGRATION AUDIT")
    print("=" * 80 + "\n")

    # Clean runtime states
    device_registry.clear()
    connection_registry.clear()
    zone_engine.clear()
    service_graph_engine.clear()
    firewall_engine.clear()

    # -------------------------------------------------------------------------
    # 1. CREATE COMPLETE CANONICAL NETWORK
    # -------------------------------------------------------------------------
    print("[1/6] Provisioning Complete Canonical Topology...")
    inet = NetworkDeviceModel(id="inet-01", hostname="INTERNET", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.EXTERNAL)
    fw = NetworkDeviceModel(id="firewall-01", hostname="FIREWALL-01", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL)
    rtr = NetworkDeviceModel(
        id="router-01", hostname="ROUTER-01", type=DeviceTypeEnum.ROUTER,
        interfaces=[
            NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.10.1", mac_address="00:50:56:FE:10:01", subnet_cidr="192.168.10.0/24"),
            NetworkInterfaceConfig(interface_id="eth1", ip_address="192.168.20.1", mac_address="00:50:56:FE:20:01", subnet_cidr="192.168.20.0/24")
        ],
        networkZone=NetworkZoneEnum.INTERNAL
    )
    sw = NetworkDeviceModel(id="switch-01", hostname="SWITCH-01", type=DeviceTypeEnum.SWITCH, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(
        id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER,
        ipAddresses=["192.168.20.10"], ports=[80, 443], services=["nginx", "web-app"], networkZone=NetworkZoneEnum.DMZ
    )
    db = NetworkDeviceModel(
        id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE,
        ipAddresses=["192.168.40.10"], ports=[5432], services=["postgresql"], networkZone=NetworkZoneEnum.INTERNAL
    )
    dns = NetworkDeviceModel(
        id="dns-01", hostname="DNS-01", type=DeviceTypeEnum.DNS_SERVER,
        ipAddresses=["192.168.20.30"], ports=[53], services=["dnsmasq"], networkZone=NetworkZoneEnum.DMZ
    )
    client = NetworkDeviceModel(
        id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT,
        ipAddresses=["192.168.30.10"], services=["browser"], networkZone=NetworkZoneEnum.INTERNAL
    )

    for d in [inet, fw, rtr, sw, web, db, dns, client]:
        device_registry.createDevice(d)

    # Assign Zones in both zone_engine and firewall_engine
    for z_id, d_id in [
        ("zone-internet", "inet-01"),
        ("zone-internet", "firewall-01"),
        ("zone-internal", "router-01"),
        ("zone-internal", "switch-01"),
        ("zone-dmz", "web-01"),
        ("zone-dmz", "dns-01"),
        ("zone-internal", "client-01"),
        ("zone-database", "db-01"),
    ]:
        zone_engine.assignDeviceToZone(z_id, d_id)
        firewall_engine.assignDeviceToZone(z_id, d_id)

    # Wire Connections (Hierarchical L2/L3 topology via switch-01)
    conns = [
        NetworkConnectionModel(id="c-inet-fw", sourceDevice="inet-01", destinationDevice="firewall-01", latency=5.0),
        NetworkConnectionModel(id="c-fw-rtr", sourceDevice="firewall-01", destinationDevice="router-01", latency=1.0),
        NetworkConnectionModel(id="c-rtr-sw", sourceDevice="router-01", destinationDevice="switch-01", latency=0.5),
        NetworkConnectionModel(id="c-sw-web", sourceDevice="switch-01", destinationDevice="web-01", latency=0.2),
        NetworkConnectionModel(id="c-sw-dns", sourceDevice="switch-01", destinationDevice="dns-01", latency=0.2),
        NetworkConnectionModel(id="c-sw-client", sourceDevice="switch-01", destinationDevice="client-01", latency=0.5),
        NetworkConnectionModel(id="c-web-db", sourceDevice="web-01", destinationDevice="db-01", protocol=ProtocolEnum.TCP, destinationPort=5432, latency=0.3)
    ]
    for c in conns:
        connection_registry.createConnection(c)

    # Wire Application Dependencies
    service_graph_engine.addDependency(DetailedServiceDependencyModel(
        id="sdep-cli-web", sourceDevice="client-01", sourceService="browser",
        destinationDevice="web-01", destinationService="web-app", protocol="TCP", port=443, criticality=ServiceCriticalityEnum.CRITICAL
    ))
    service_graph_engine.addDependency(DetailedServiceDependencyModel(
        id="sdep-web-db", sourceDevice="web-01", sourceService="web-app",
        destinationDevice="db-01", destinationService="postgresql", protocol="TCP", port=5432, criticality=ServiceCriticalityEnum.HIGH
    ))

    # Configure Firewall Rules
    # Rule 1: Internet -> DMZ (ALLOW TCP 443)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-inet-dmz", sourceZone=NetworkZoneTypeEnum.INTERNET, destinationZone=NetworkZoneTypeEnum.DMZ,
        protocol="TCP", destinationPort=443, action=FirewallActionEnum.ALLOW
    ))
    # Rule 2: Internal -> DMZ (ALLOW TCP 443)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-internal-dmz", sourceZone=NetworkZoneTypeEnum.INTERNAL, destinationZone=NetworkZoneTypeEnum.DMZ,
        protocol="TCP", destinationPort=443, action=FirewallActionEnum.ALLOW
    ))
    # Rule 3: DMZ -> Database (ALLOW TCP 5432)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-dmz-db", sourceZone=NetworkZoneTypeEnum.DMZ, destinationZone=NetworkZoneTypeEnum.DATABASE,
        protocol="TCP", destinationPort=5432, action=FirewallActionEnum.ALLOW
    ))

    print(f"    [PASS] Network provisioned: {device_registry.count()} devices, {connection_registry.count()} connections, {len(zone_engine.listZones())} zones.")

    # -------------------------------------------------------------------------
    # 2. GENERATE DIGITAL TWIN SNAPSHOT
    # -------------------------------------------------------------------------
    print("\n[2/6] Generating Digital Twin Day 42 Snapshot...")
    snapshot = complete_graph_engine.generateDay42Snapshot()
    print(f"    Network Overview: Devices={snapshot['network']['devices']}, Connections={snapshot['network']['connections']}, Zones={snapshot['network']['zones']}")
    print(f"    Topology Reachable: {snapshot['topology']['reachable']}")
    assert snapshot["network"]["devices"] == 8
    assert snapshot["network"]["connections"] >= 7
    assert snapshot["network"]["zones"] >= 4
    assert snapshot["topology"]["reachable"] is True
    print("    [PASS] Digital Twin Snapshot successfully validated.")

    # -------------------------------------------------------------------------
    # 3. TEST DEVICE FAILURE & STATE PROPAGATION
    # -------------------------------------------------------------------------
    print("\n[3/6] Testing Device Failure & Service State Propagation (WEB-01 -> OFFLINE)...")
    web.currentState = "OFFLINE"
    device_registry.updateDevice(web)

    # Test reachability from client to web
    reach_web = reachability_engine.isReachable("client-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_web.is_reachable is False
    assert "is OFFLINE" in reach_web.blocking_reason
    print(f"    Reachability Client -> Web-01: {reach_web.is_reachable} ({reach_web.blocking_reason})")

    # Test impact propagation
    impact_web = service_graph_engine.propagateImpact("web-01", "web-app")
    assert impact_web.total_impacted_services >= 1
    assert any(s.device_id == "client-01" for s in impact_web.impacted_services)
    print(f"    Impact Cascade: {impact_web.total_impacted_services} services impacted across {impact_web.total_impacted_devices} devices.")
    print("    [PASS] Device failure state propagation verified.")

    # Restore web-01
    web.currentState = "ONLINE"
    device_registry.updateDevice(web)

    # -------------------------------------------------------------------------
    # 4. TEST CONNECTION FAILURE
    # -------------------------------------------------------------------------
    print("\n[4/6] Testing Connection Failure (Switch-01 <-> Web-01 -> BLOCKED)...")
    c_sw_web = connection_registry.getConnection("c-sw-web")
    c_sw_web.status = ConnectionStatusEnum.BLOCKED
    connection_registry.updateConnection(c_sw_web)

    reach_conn_fail = reachability_engine.isReachable("client-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_conn_fail.is_reachable is False
    assert "is BLOCKED" in reach_conn_fail.blocking_reason
    print(f"    Reachability after severed link: {reach_conn_fail.is_reachable} ({reach_conn_fail.blocking_reason})")
    print("    [PASS] Link failure severed reachability as expected.")

    # Restore link
    c_sw_web.status = ConnectionStatusEnum.ACTIVE
    connection_registry.updateConnection(c_sw_web)

    # -------------------------------------------------------------------------
    # 5. TEST FIREWALL DYNAMIC RECONFIGURATION
    # -------------------------------------------------------------------------
    print("\n[5/6] Testing Dynamic Firewall Policy Mutation (ALLOW -> DENY)...")
    # Verify reachable initially
    reach_fw_allow = reachability_engine.isReachable("inet-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_fw_allow.is_reachable is True
    print(f"    Initial Internet -> Web-01 (TCP 443): Reachable = {reach_fw_allow.is_reachable}")

    # Mutate rule to DENY
    rule_inet = firewall_engine.listRules()[0]
    firewall_engine.removeRule(rule_inet.id)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-inet-dmz-deny", sourceZone=NetworkZoneTypeEnum.INTERNET, destinationZone=NetworkZoneTypeEnum.DMZ,
        protocol="TCP", destinationPort=443, action=FirewallActionEnum.DENY
    ))

    reach_fw_deny = reachability_engine.isReachable("inet-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_fw_deny.is_reachable is False
    assert "Firewall policy DENIED" in reach_fw_deny.blocking_reason
    print(f"    Mutated Policy (TCP 443 -> DENY)   : Reachable = {reach_fw_deny.is_reachable} ({reach_fw_deny.blocking_reason})")
    print("    [PASS] Dynamic firewall enforcement verified.")

    # -------------------------------------------------------------------------
    # 6. COMPREHENSIVE FAILURE AND REJECTION SUITE (13 CASES)
    # -------------------------------------------------------------------------
    print("\n[6/6] Executing 13 Boundary Failure & Rejection Tests...")

    # 1. Unknown device
    try:
        connection_registry.createConnection(NetworkConnectionModel(id="c-unk-1", sourceDevice="ghost-dev", destinationDevice="web-01"))
        assert False
    except DeviceNotFoundError:
        print("    [1/13] [PASS] Rejected unknown source device.")

    # 2. Unknown connection
    try:
        connection_registry.deleteConnection("ghost-conn-999")
        assert False
    except ConnectionNotFoundError:
        print("    [2/13] [PASS] Rejected unknown connection deletion.")

    # 3. Unknown zone
    try:
        zone_engine.assignDeviceToZone("ghost-zone-999", "web-01")
        assert False
    except ZoneNotFoundError:
        print("    [3/13] [PASS] Rejected unknown zone assignment.")

    # 4. Duplicate node
    try:
        device_registry.createDevice(web)
        assert False
    except DeviceAlreadyExistsError:
        print("    [4/13] [PASS] Rejected duplicate device ID.")

    # 5. Duplicate edge
    try:
        connection_registry.createConnection(conns[0])
        assert False
    except ConnectionAlreadyExistsError:
        print("    [5/13] [PASS] Rejected duplicate connection ID.")

    # 6. Invalid IP
    try:
        NetworkDeviceModel(id="bad-ip-dev", hostname="bad-ip", type=DeviceTypeEnum.CLIENT, ipAddresses=["999.999.999.999"])
        assert False
    except ValidationError:
        print("    [6/13] [PASS] Rejected malformed IP address.")

    # 7. Invalid Port
    try:
        NetworkConnectionModel(id="bad-port-conn", sourceDevice="inet-01", destinationDevice="web-01", destinationPort=70000)
        assert False
    except ValidationError:
        print("    [7/13] [PASS] Rejected out-of-range port (>65535).")

    # 8. Invalid Protocol
    try:
        NetworkConnectionModel(id="bad-proto-conn", sourceDevice="inet-01", destinationDevice="web-01", protocol="QUANTUM_TELEPATHY")
        assert False
    except ValidationError:
        print("    [8/13] [PASS] Rejected invalid protocol enum.")

    # 9. Invalid Zone
    try:
        NetworkDeviceModel(id="bad-zone-dev", hostname="bad-zone", type=DeviceTypeEnum.CLIENT, networkZone="SECRET_UNDERGROUND_ZONE")
        assert False
    except ValidationError:
        print("    [9/13] [PASS] Rejected invalid network zone.")

    # 10. Disconnected device
    disc_dev = NetworkDeviceModel(id="disconnected-pc", hostname="ISOLATED-PC", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    device_registry.createDevice(disc_dev)
    reach_disc = reachability_engine.isReachable("disconnected-pc", "web-01", protocol="TCP", destination_port=443)
    assert reach_disc.is_reachable is False
    print("    [10/13] [PASS] Confirmed unreachable for disconnected device.")

    # 11. Offline router
    # Restore firewall allow rule so router is the sole blocking factor
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-inet-dmz-restore", sourceZone=NetworkZoneTypeEnum.INTERNET, destinationZone=NetworkZoneTypeEnum.DMZ,
        protocol="TCP", destinationPort=443, action=FirewallActionEnum.ALLOW, priority=1
    ))
    rtr.currentState = "OFFLINE"
    device_registry.updateDevice(rtr)
    # inet-01 -> web-01 must transit router-01
    reach_rtr_off = reachability_engine.isReachable("inet-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_rtr_off.is_reachable is False
    assert "is OFFLINE" in reach_rtr_off.blocking_reason
    print("    [11/13] [PASS] Confirmed offline router severs routing paths.")
    rtr.currentState = "ONLINE"
    device_registry.updateDevice(rtr)

    # 12. Offline firewall
    fw.currentState = "OFFLINE"
    device_registry.updateDevice(fw)
    reach_fw_off = reachability_engine.isReachable("inet-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_fw_off.is_reachable is False
    print("    [12/13] [PASS] Confirmed offline firewall severs perimeter reachability.")
    fw.currentState = "ONLINE"
    device_registry.updateDevice(fw)

    # 13. Blocked connection
    conns[0].status = ConnectionStatusEnum.BLOCKED
    connection_registry.updateConnection(conns[0])
    reach_blocked = reachability_engine.isReachable("inet-01", "web-01", protocol="TCP", destination_port=443)
    assert reach_blocked.is_reachable is False
    print("    [13/13] [PASS] Confirmed blocked connection drops traffic.")

    print("\n" + "=" * 80)
    print("   PHASE 5 GRAND INTEGRATION AUDIT: ALL 6 PHASES & 13 BOUNDARY TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_day42_master_integration()