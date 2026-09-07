import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.zone_graph import ZoneDefinitionModel
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.zone_engine import zone_engine

def run_zone_graph_suite():
    print("================================================================================")
    print("       WEEK 6 - DAY 38: ZONE SEGMENTATION GRAPH AUDIT                           ")
    print("================================================================================\n")

    device_registry.clear()
    connection_registry.clear()
    zone_engine.clear()

    # 1. Provision Canonical Devices
    print("[1/5] Provisioning Devices for Zone Graph Modeling...")
    fw = NetworkDeviceModel(id="fw-01", hostname="Firewall-Edge", type=DeviceTypeEnum.FIREWALL)
    web = NetworkDeviceModel(id="web-01", hostname="Web-Server", type=DeviceTypeEnum.SERVER, ports=[80, 443])
    pc = NetworkDeviceModel(id="client-01", hostname="Workstation-01", type=DeviceTypeEnum.CLIENT)
    db = NetworkDeviceModel(id="db-01", hostname="DB-Server", type=DeviceTypeEnum.DATABASE, ports=[5432])

    for d in [fw, web, pc, db]:
        device_registry.createDevice(d)

    assert device_registry.count() == 4
    print("    [PASS] 4 devices registered.")

    # 2. Assign Devices into Zones
    print("\n[2/5] Assigning Devices into Strategic Security Zones...")
    zone_engine.assignDeviceToZone("zone-internet", "fw-01")
    zone_engine.assignDeviceToZone("zone-dmz", "web-01")
    zone_engine.assignDeviceToZone("zone-internal", "client-01")
    zone_engine.assignDeviceToZone("zone-database", "db-01")

    assert "fw-01" in zone_engine.getZoneDevices("zone-internet")
    assert "web-01" in zone_engine.getZoneDevices("zone-dmz")
    assert "client-01" in zone_engine.getZoneDevices("zone-internal")
    assert "db-01" in zone_engine.getZoneDevices("zone-database")
    print("    [PASS] Devices assigned to respective security zones.")

    # 3. Establish Inter-Zone Connections
    print("\n[3/5] Wiring Connections Across Zone Boundaries...")
    # Internet (fw) -> DMZ (web)
    connection_registry.createConnection(NetworkConnectionModel(
        id="c-inet-web", sourceDevice="fw-01", destinationDevice="web-01",
        connectionType=ConnectionTypeEnum.NETWORK, protocol=ProtocolEnum.TCP, destinationPort=443
    ))
    # DMZ (web) -> Internal (client-01 for API integration)
    connection_registry.createConnection(NetworkConnectionModel(
        id="c-web-internal", sourceDevice="web-01", destinationDevice="client-01",
        connectionType=ConnectionTypeEnum.NETWORK, protocol=ProtocolEnum.TCP, destinationPort=8080
    ))
    # Internal (client-01) -> Database (db-01)
    connection_registry.createConnection(NetworkConnectionModel(
        id="c-internal-db", sourceDevice="client-01", destinationDevice="db-01",
        connectionType=ConnectionTypeEnum.NETWORK, protocol=ProtocolEnum.TCP, destinationPort=5432
    ))

    assert connection_registry.count() == 3
    print("    [PASS] 3 perimeter boundary connections established.")

    # 4. Inspect Zone Connections
    print("\n[4/5] Inspecting Inter-Zone Links for DMZ (zone-dmz)...")
    dmz_conns = zone_engine.getZoneConnections("zone-dmz")
    print(f"    DMZ Links Count: {len(dmz_conns)}")
    for link in dmz_conns:
        print(f"    - Link [{link.connection_id}]: {link.source_device} ({link.source_zone}) -> {link.destination_device} ({link.destination_zone}) [Inter-Zone: {link.is_inter_zone}]")

    assert len(dmz_conns) == 2
    assert all(c.is_inter_zone for c in dmz_conns)
    print("    [PASS] Correctly categorized perimeter boundary links.")

    # 5. Build and Verify Condensed Zone Segmentation Graph
    print("\n[5/5] Building Macro Zone Segmentation Graph...")
    zone_graph = zone_engine.buildZoneSegmentationGraph()
    print(f"    Total Security Zones: {zone_graph.zone_count}")
    print(f"    Total Inter-Zone Links: {len(zone_graph.inter_zone_links)}")
    print("    Zone Adjacency Map:")
    for src_z, dst_list in zone_graph.zone_adjacency.items():
        if dst_list:
            print(f"      {src_z} ---> {dst_list}")

    assert "zone-dmz" in zone_graph.zone_adjacency["zone-internet"]
    assert "zone-internal" in zone_graph.zone_adjacency["zone-dmz"]
    assert "zone-database" in zone_graph.zone_adjacency["zone-internal"]
    print("    [PASS] Zone Graph confirms traversal: INTERNET -> DMZ -> INTERNAL -> DATABASE.")

    print("\n================================================================================")
    print("       ALL ZONE SEGMENTATION GRAPH AUDIT TESTS PASSED CLEANLY                   ")
    print("================================================================================")

if __name__ == "__main__":
    run_zone_graph_suite()