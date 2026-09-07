import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from services.digital_twin.core.topology.topology_engine_v2 import topology_engine

def run_topology_engine_suite():
    print("================================================================================")
    print("       WEEK 6 - DAY 37: TOPOLOGY ENGINE & GRAPH SYNTHESIS AUDIT                 ")
    print("================================================================================\n")

    topology_engine.clear()

    # 1. Provision the 8 Canonical Devices across 4 Zones
    print("[1/5] Provisioning 8 Canonical Devices across 4 Zones...")
    devices = [
        NetworkDeviceModel(id="dev-inet", hostname="Internet", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.EXTERNAL, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-fw", hostname="Firewall", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-rtr", hostname="Router", type=DeviceTypeEnum.ROUTER, networkZone=NetworkZoneEnum.INTERNAL, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-sw", hostname="Switch", type=DeviceTypeEnum.SWITCH, networkZone=NetworkZoneEnum.INTERNAL, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-pc1", hostname="PC1", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-web", hostname="Web", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-dns", hostname="DNS", type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.INTERNAL, currentState="ONLINE"),
        NetworkDeviceModel(id="dev-db", hostname="DB", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, currentState="OFFLINE") # 1 Inactive
    ]

    for d in devices:
        topology_engine.addDevice(d)

    print("    [PASS] 8 devices registered in topology engine.")

    # 2. Establish the 9 Connections
    print("\n[2/5] Creating 9 Connections to Build Example Topology...")
    connections = [
        NetworkConnectionModel(id="c-inet-fw", sourceDevice="dev-inet", destinationDevice="dev-fw", connectionType=ConnectionTypeEnum.PHYSICAL, latency=5.0),
        NetworkConnectionModel(id="c-fw-rtr", sourceDevice="dev-fw", destinationDevice="dev-rtr", connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.5),
        NetworkConnectionModel(id="c-rtr-sw", sourceDevice="dev-rtr", destinationDevice="dev-sw", connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.2),
        NetworkConnectionModel(id="c-sw-pc1", sourceDevice="dev-sw", destinationDevice="dev-pc1", connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.5),
        NetworkConnectionModel(id="c-sw-web", sourceDevice="dev-sw", destinationDevice="dev-web", connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.3),
        NetworkConnectionModel(id="c-sw-dns", sourceDevice="dev-sw", destinationDevice="dev-dns", connectionType=ConnectionTypeEnum.PHYSICAL, latency=0.4),
        NetworkConnectionModel(id="c-web-db", sourceDevice="dev-web", destinationDevice="dev-db", connectionType=ConnectionTypeEnum.NETWORK, protocol=ProtocolEnum.TCP, destinationPort=5432, latency=0.2),
        NetworkConnectionModel(id="c-pc1-dns", sourceDevice="dev-pc1", destinationDevice="dev-dns", connectionType=ConnectionTypeEnum.SERVICE, protocol=ProtocolEnum.UDP, destinationPort=53, latency=0.1),
        NetworkConnectionModel(id="c-pc1-web", sourceDevice="dev-pc1", destinationDevice="dev-web", connectionType=ConnectionTypeEnum.SERVICE, protocol=ProtocolEnum.TCP, destinationPort=443, latency=0.2)
    ]

    for c in connections:
        topology_engine.connectDevices(c)

    print("    [PASS] 9 connections registered.")

    # 3. Pathfinding Verification (PC1 -> Switch -> Router -> Firewall -> Internet)
    print("\n[3/5] Testing Pathfinding: PC1 -> Internet...")
    path = topology_engine.findPath("dev-pc1", "dev-inet")
    print(f"    Path: {' -> '.join(path.traversed_devices)} ({path.hop_count} hops, {path.total_latency_ms} ms)")
    assert path.is_connected is True
    assert path.path_hops == ["dev-pc1", "dev-sw", "dev-rtr", "dev-fw", "dev-inet"]
    print("    [PASS] Transits through Switch, Router, and Firewall.")

    # 4. Isolated & Inactive Device Detection
    print("\n[4/5] Testing Isolated & Inactive Device Detection...")
    isolated = topology_engine.detectIsolatedDevices()
    print(f"    Detected Inactive/Isolated Devices: {isolated}")
    assert "dev-db" in isolated
    print("    [PASS] Offline Database server correctly identified.")

    # 5. Generate Snapshot
    print("\n[5/5] Generating Topology Snapshot Summary...")
    snapshot = topology_engine.generateTopologySnapshot()
    print(f"    Nodes          : {snapshot.nodes}")
    print(f"    Edges          : {snapshot.edges}")
    print(f"    Zones          : {snapshot.zones}")
    print(f"    ActiveDevices  : {snapshot.activeDevices}")
    print(f"    InactiveDevices: {snapshot.inactiveDevices}")
    print(f"    Timestamp      : {snapshot.timestamp}")

    assert snapshot.nodes == 8
    assert snapshot.edges == 9
    assert snapshot.activeDevices == 7
    assert snapshot.inactiveDevices == 1

    print("\n================================================================================")
    print("       ALL TOPOLOGY ENGINE AUDIT TESTS PASSED CLEANLY                           ")
    print("================================================================================")

if __name__ == "__main__":
    run_topology_engine_suite()