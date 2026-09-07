import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.firewall import FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.topology.reachability_engine import reachability_engine

def run_reachability_engine_suite():
    print("================================================================================")
    print("       WEEK 6 - DAY 39: PATH FINDING & REACHABILITY ENGINE AUDIT                ")
    print("================================================================================\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    firewall_engine.clear()

    # 1. Provision Canonical Devices: Internet -> Firewall -> Router -> Web Server -> Database
    print("[1/5] Provisioning Multi-Tier Topology (Internet -> Firewall -> Router -> Web -> DB)...")
    inet = NetworkDeviceModel(id="dev-inet", hostname="Internet", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.EXTERNAL)
    fw = NetworkDeviceModel(id="dev-fw", hostname="Firewall", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL)
    rtr = NetworkDeviceModel(id="dev-rtr", hostname="Router", type=DeviceTypeEnum.ROUTER, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="dev-web", hostname="Web-Server", type=DeviceTypeEnum.SERVER, ports=[80, 443], networkZone=NetworkZoneEnum.DMZ)
    db = NetworkDeviceModel(id="dev-db", hostname="Database-Server", type=DeviceTypeEnum.DATABASE, ports=[5432], networkZone=NetworkZoneEnum.INTERNAL)

    for d in [inet, fw, rtr, web, db]:
        device_registry.createDevice(d)
        graph_engine.addNode(d)

    # 2. Zone Mapping & Firewall Policies
    firewall_engine.assignDeviceToZone("zone-internet", "dev-inet")
    firewall_engine.assignDeviceToZone("zone-internet", "dev-fw")
    firewall_engine.assignDeviceToZone("zone-dmz", "dev-web")
    firewall_engine.assignDeviceToZone("zone-database", "dev-db")

    # Policy 1: Internet -> DMZ (ALLOW TCP:443)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-https", sourceZone=NetworkZoneTypeEnum.INTERNET, destinationZone=NetworkZoneTypeEnum.DMZ,
        protocol="TCP", destinationPort=443, action=FirewallActionEnum.ALLOW
    ))

    # Policy 2: DMZ -> Database (ALLOW TCP:5432)
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-db", sourceZone=NetworkZoneTypeEnum.DMZ, destinationZone=NetworkZoneTypeEnum.DATABASE,
        protocol="TCP", destinationPort=5432, action=FirewallActionEnum.ALLOW
    ))

    # 3. Connect Topology Edges
    print("\n[2/5] Wiring Sequential Links...")
    conns = [
        NetworkConnectionModel(id="c-inet-fw", sourceDevice="dev-inet", destinationDevice="dev-fw", latency=5.0),
        NetworkConnectionModel(id="c-fw-rtr", sourceDevice="dev-fw", destinationDevice="dev-rtr", latency=1.0),
        NetworkConnectionModel(id="c-rtr-web", sourceDevice="dev-rtr", destinationDevice="dev-web", latency=0.5),
        NetworkConnectionModel(id="c-web-db", sourceDevice="dev-web", destinationDevice="dev-db", latency=0.5)
    ]
    for c in conns:
        connection_registry.createConnection(c)
        graph_engine.addEdge(c, is_bidirectional=True)

    print("    [PASS] 4 connections established across 5 nodes.")

    # 4. Unweighted BFS Path Discovery
    print("\n[3/5] Testing Unweighted BFS Path Discovery: Internet -> Database...")
    bfs_path = reachability_engine.findPath("dev-inet", "dev-db")
    print(f"    BFS Discovered Path: {' -> '.join(bfs_path)} ({len(bfs_path) - 1} hops)")
    assert bfs_path == ["dev-inet", "dev-fw", "dev-rtr", "dev-web", "dev-db"]
    print("    [PASS] BFS path accurately reflects physical topology.")

    # 5. Security-Constrained Reachability Checks
    print("\n[4/5] Testing Security-Constrained Reachability...")

    # Case A: Internet -> Web Server on TCP:443 (EXPECT REACHABLE)
    res_a = reachability_engine.isReachable("dev-inet", "dev-web", protocol="TCP", destination_port=443)
    print(f"    Internet -> Web Server (TCP:443) : Reachable = {res_a.is_reachable} (Latency = {res_a.total_latency_ms} ms)")
    assert res_a.is_reachable is True

    # Case B: Internet -> Database on TCP:5432 (EXPECT BLOCKED by Firewall)
    res_b = reachability_engine.isReachable("dev-inet", "dev-db", protocol="TCP", destination_port=5432)
    print(f"    Internet -> Database (TCP:5432)   : Reachable = {res_b.is_reachable} (Reason: {res_b.blocking_reason})")
    assert res_b.is_reachable is False
    assert "Firewall policy DENIED" in res_b.blocking_reason

    # Case C: Internet -> Web Server on Closed Port 2222 (EXPECT BLOCKED)
    res_c = reachability_engine.isReachable("dev-inet", "dev-web", protocol="TCP", destination_port=2222)
    print(f"    Internet -> Web Server (TCP:2222): Reachable = {res_c.is_reachable} (Reason: {res_c.blocking_reason})")
    assert res_c.is_reachable is False
    assert "Port 2222 is not listening" in res_c.blocking_reason

    # 6. Operational Severance Check (Taking Router Offline)
    print("\n[5/5] Testing Operational Severance (Marking Router OFFLINE)...")
    rtr.currentState = "OFFLINE"
    device_registry.updateDevice(rtr)

    res_d = reachability_engine.isReachable("dev-inet", "dev-web", protocol="TCP", destination_port=443)
    print(f"    Internet -> Web Server (Router OFFLINE): Reachable = {res_d.is_reachable} (Reason: {res_d.blocking_reason})")
    assert res_d.is_reachable is False
    assert "is OFFLINE" in res_d.blocking_reason
    print("    [PASS] Offline intermediate hop correctly severs reachability.")

    print("\n================================================================================")
    print("       ALL REACHABILITY ENGINE AUDIT TESTS PASSED CLEANLY                       ")
    print("================================================================================")

if __name__ == "__main__":
    run_reachability_engine_suite()