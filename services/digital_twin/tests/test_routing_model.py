import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, 
    NetworkInterfaceConfig, RouteEntryModel
)
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.routing_engine import routing_engine

def run_routing_model_suite():
    print("================================================================================")
    print("       WEEK 5 - DAY 32: ROUTER FORWARDING & ROUTING MODEL AUDIT                 ")
    print("================================================================================\n")

    device_registry.clear()
    connection_registry.clear()

    # 1. Setup Canonical Lab Topology:
    # Internet (8.8.8.8) <-> Router (rtr-01) <-> Switch (sw-01) <-> PC1 & PC2
    print("[1/5] Provisioning Lab Topology (Router, Switch, PC1, PC2)...")
    router = NetworkDeviceModel(
        id="rtr-01",
        hostname="router-01",
        type=DeviceTypeEnum.ROUTER,
        ipAddresses=["192.168.1.1", "203.0.113.5"],
        interfaces=[
            NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.1.1", mac_address="00:50:56:FE:01:00", subnet_cidr="192.168.1.0/24"),
            NetworkInterfaceConfig(interface_id="wan0", ip_address="203.0.113.5", mac_address="00:50:56:FE:01:01", subnet_cidr="203.0.113.0/30")
        ],
        networkZone=NetworkZoneEnum.EXTERNAL
    )

    switch = NetworkDeviceModel(
        id="sw-01",
        hostname="switch-01",
        type=DeviceTypeEnum.SWITCH,
        networkZone=NetworkZoneEnum.INTERNAL
    )

    pc1 = NetworkDeviceModel(
        id="pc-01",
        hostname="pc-01",
        type=DeviceTypeEnum.CLIENT,
        ipAddresses=["192.168.1.11"],
        interfaces=[
            NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.1.11", mac_address="00:50:56:FE:01:11", subnet_cidr="192.168.1.0/24")
        ],
        networkZone=NetworkZoneEnum.INTERNAL
    )

    pc2 = NetworkDeviceModel(
        id="pc-02",
        hostname="pc-02",
        type=DeviceTypeEnum.CLIENT,
        ipAddresses=["192.168.1.12"],
        interfaces=[
            NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.1.12", mac_address="00:50:56:FE:01:12", subnet_cidr="192.168.1.0/24")
        ],
        networkZone=NetworkZoneEnum.INTERNAL
    )

    for d in [router, switch, pc1, pc2]:
        device_registry.createDevice(d)

    # Connect Topology
    connection_registry.createConnection(NetworkConnectionModel(id="c-pc1-sw", sourceDevice="pc-01", destinationDevice="sw-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-pc2-sw", sourceDevice="pc-02", destinationDevice="sw-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    connection_registry.createConnection(NetworkConnectionModel(id="c-sw-rtr", sourceDevice="sw-01", destinationDevice="rtr-01", connectionType=ConnectionTypeEnum.PHYSICAL))
    print("    [+] Topology created successfully.")

    # 2. Populate Routing Table on Router
    print("\n[2/5] Injecting Routes into router-01 Routing Table...")
    # Route 1: Local LAN
    routing_engine.addRoute("rtr-01", RouteEntryModel(destination="192.168.1.0/24", nextHop="DIRECT", interface="eth0", metric=1))
    # Route 2: Specific Engineering Subnet (for testing LPM)
    routing_engine.addRoute("rtr-01", RouteEntryModel(destination="192.168.1.128/28", nextHop="DIRECT", interface="eth0.128", metric=1))
    # Route 3: Default Route to Internet
    routing_engine.addRoute("rtr-01", RouteEntryModel(destination="0.0.0.0/0", nextHop="203.0.113.1", interface="wan0", metric=10))

    routes = routing_engine.getRoutingTable("rtr-01")
    assert len(routes) == 3
    print(f"    [PASS] Configured {len(routes)} active routes on rtr-01.")

    # 3. Test Longest-Prefix Match (LPM) Selection
    print("\n[3/5] Testing Longest-Prefix Match Forwarding...")
    # Case A: IP 192.168.1.130 matches /28 (specific subnet)
    res_specific = routing_engine.findRoute("rtr-01", "192.168.1.130")
    print(f"    192.168.1.130 -> Egress: {res_specific.egress_interface} (Prefix: {res_specific.matched_route.destination})")
    assert res_specific.egress_interface == "eth0.128"
    assert res_specific.matched_route.destination == "192.168.1.128/28"

    # Case B: IP 192.168.1.11 matches /24 (general LAN)
    res_lan = routing_engine.findRoute("rtr-01", "192.168.1.11")
    print(f"    192.168.1.11  -> Egress: {res_lan.egress_interface} (Prefix: {res_lan.matched_route.destination})")
    assert res_lan.egress_interface == "eth0"
    assert res_lan.is_direct is True

    # Case C: IP 8.8.8.8 matches /0 (Internet Default Route)
    res_wan = routing_engine.findRoute("rtr-01", "8.8.8.8")
    print(f"    8.8.8.8       -> Egress: {res_wan.egress_interface} (Next Hop: {res_wan.next_hop})")
    assert res_wan.egress_interface == "wan0"
    assert res_wan.next_hop == "203.0.113.1"
    assert res_wan.matched_route.destination == "0.0.0.0/0"
    print("    [PASS] Longest-prefix match successfully prioritized /28 over /24 over /0.")

    # 4. Practical: PC1 -> Router -> Internet Path Verification
    print("\n[4/5] Practical Test: Trace Packet Flow from PC1 (192.168.1.11) to Internet (8.8.8.8)...")
    trace = routing_engine.traceLayer3Path(source_device_id="pc-01", destination_ip="8.8.8.8")
    for hop in trace:
        print(f"    Hop {hop['hop']}: Node [{hop.get('device_id')}] -> Action: {hop['action']}")

    assert trace[0]["action"] == "FORWARD_TO_DEFAULT_GATEWAY"
    assert trace[1]["device_id"] == "rtr-01"
    assert trace[1]["matched_prefix"] == "0.0.0.0/0"
    assert trace[1]["egress_interface"] == "wan0"
    print("    [PASS] PC1 -> Router -> Internet forwarding path validated.")

    # 5. Route Deletion Verification
    print("\n[5/5] Testing Route Removal...")
    routing_engine.removeRoute("rtr-01", "192.168.1.128/28")
    updated_routes = routing_engine.getRoutingTable("rtr-01")
    assert len(updated_routes) == 2
    assert not any(r.destination == "192.168.1.128/28" for r in updated_routes)
    print("    [PASS] Specific route removed; routing table updated dynamically.")

    print("\n================================================================================")
    print("       ALL 5 ROUTING & FORWARDING TESTS PASSED CLEANLY                          ")
    print("================================================================================")

if __name__ == "__main__":
    run_routing_model_suite()