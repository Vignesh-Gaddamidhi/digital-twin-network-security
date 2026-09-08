import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.service_graph import DetailedServiceDependencyModel, ServiceCriticalityEnum
from packages.shared_types.src.firewall import FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.zone_engine import zone_engine
from services.digital_twin.core.topology.service_graph_engine import service_graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.topology.complete_graph_engine import complete_graph_engine

def run_complete_graph_suite():
    print("================================================================================")
    print("       WEEK 6 - DAY 41: COMPLETE DIGITAL TWIN GRAPH AUDIT                       ")
    print("================================================================================\n")

    # Clear previous runtime state
    device_registry.clear()
    connection_registry.clear()
    zone_engine.clear()
    service_graph_engine.clear()
    firewall_engine.clear()

    # 1. Provision the 6 Canonical Devices
    print("[1/5] Instantiating 6 Canonical Devices (Firewall, Router, Web, DB, DNS, Clients)...")
    fw = NetworkDeviceModel(id="fw-01", hostname="Firewall-01", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL)
    rtr = NetworkDeviceModel(id="rtr-01", hostname="Router-01", type=DeviceTypeEnum.ROUTER, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="Web-Server-01", type=DeviceTypeEnum.SERVER, ports=[80, 443], networkZone=NetworkZoneEnum.DMZ)
    db = NetworkDeviceModel(id="db-01", hostname="DB-Server-01", type=DeviceTypeEnum.DATABASE, ports=[5432], networkZone=NetworkZoneEnum.INTERNAL)
    dns = NetworkDeviceModel(id="dns-01", hostname="DNS-Server-01", type=DeviceTypeEnum.DNS_SERVER, ports=[53], networkZone=NetworkZoneEnum.INTERNAL)
    client = NetworkDeviceModel(id="client-01", hostname="Client-Workstation", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)

    for d in [fw, rtr, web, db, dns, client]:
        device_registry.createDevice(d)

    assert device_registry.count() == 6
    print("    [PASS] 6 devices registered.")

    # 2. Assign Devices into the 4 Zones
    print("\n[2/5] Assigning Devices into 4 Canonical Zones (Internet, DMZ, Internal, Database)...")
    zone_engine.assignDeviceToZone("zone-internet", "fw-01")
    zone_engine.assignDeviceToZone("zone-dmz", "web-01")
    zone_engine.assignDeviceToZone("zone-database", "db-01")
    zone_engine.assignDeviceToZone("zone-internal", "client-01")
    zone_engine.assignDeviceToZone("zone-internal", "dns-01")
    zone_engine.assignDeviceToZone("zone-internal", "rtr-01")

    assert len(zone_engine.listZones()) >= 4
    print("    [PASS] Devices clustered into 4 security zones.")

    # 3. Create Network Edges (Connections)
    print("\n[3/5] Wiring Canonical Network Edges...")
    edges = [
        NetworkConnectionModel(id="c-fw-rtr", sourceDevice="fw-01", destinationDevice="rtr-01", connectionType=ConnectionTypeEnum.PHYSICAL, latency=1.0),
        NetworkConnectionModel(id="c-rtr-web", sourceDevice="rtr-01", destinationDevice="web-01", connectionType=ConnectionTypeEnum.LOGICAL, latency=0.5),
        NetworkConnectionModel(id="c-rtr-db", sourceDevice="rtr-01", destinationDevice="db-01", connectionType=ConnectionTypeEnum.LOGICAL, latency=0.5),
        NetworkConnectionModel(id="c-rtr-dns", sourceDevice="rtr-01", destinationDevice="dns-01", connectionType=ConnectionTypeEnum.LOGICAL, latency=0.4),
        NetworkConnectionModel(id="c-web-db", sourceDevice="web-01", destinationDevice="db-01", connectionType=ConnectionTypeEnum.NETWORK, protocol=ProtocolEnum.TCP, destinationPort=5432, latency=0.2)
    ]
    for e in edges:
        connection_registry.createConnection(e)

    assert connection_registry.count() == 5
    print("    [PASS] 5 connections established.")

    # 4. Create Service Dependencies
    print("\n[4/5] Wiring Layer 7 Application Dependencies (HTTPS, PostgreSQL, DNS)...")
    deps = [
        DetailedServiceDependencyModel(
            id="sdep-cli-web", sourceDevice="client-01", sourceService="browser",
            destinationDevice="web-01", destinationService="web-app", protocol="TCP", port=443, criticality=ServiceCriticalityEnum.CRITICAL
        ),
        DetailedServiceDependencyModel(
            id="sdep-web-db", sourceDevice="web-01", sourceService="web-app",
            destinationDevice="db-01", destinationService="postgresql", protocol="TCP", port=5432, criticality=ServiceCriticalityEnum.HIGH
        ),
        DetailedServiceDependencyModel(
            id="sdep-cli-dns", sourceDevice="client-01", sourceService="resolver",
            destinationDevice="dns-01", destinationService="dnsmasq", protocol="UDP", port=53, criticality=ServiceCriticalityEnum.HIGH
        )
    ]
    for d in deps:
        service_graph_engine.addDependency(d)

    assert len(service_graph_engine.listDependencies()) == 3
    print("    [PASS] 3 application dependencies mapped.")

    # 5. Extract and Validate the Complete Digital Twin Graph
    print("\n[5/5] Extracting Complete Multilayer Digital Twin Graph...")
    complete_graph = complete_graph_engine.getCompleteDigitalTwinGraph(graph_id="DT-FINAL-GRAPH-01")

    print(f"    Graph Identifier            : {complete_graph.graph_id}")
    print(f"    Summary Devices Count       : {complete_graph.summary.total_devices}")
    print(f"    Summary Connections Count   : {complete_graph.summary.total_connections}")
    print(f"    Summary Zones Count         : {complete_graph.summary.total_zones}")
    print(f"    Summary Dependencies Count  : {complete_graph.summary.total_dependencies}")
    print(f"    Active Devices Count        : {complete_graph.summary.active_devices_count}")
    print(f"    Average Latency             : {complete_graph.summary.average_latency_ms} ms")

    # Assertions
    assert complete_graph.summary.total_devices == 6
    assert complete_graph.summary.total_connections == 5
    assert complete_graph.summary.total_zones >= 4
    assert complete_graph.summary.total_dependencies == 3
    assert complete_graph.summary.active_devices_count == 6
    assert complete_graph.summary.compromised_devices_count == 0

    print("\n================================================================================")
    print("       ALL COMPLETE DIGITAL TWIN GRAPH TESTS PASSED CLEANLY                     ")
    print("================================================================================")

if __name__ == "__main__":
    run_complete_graph_suite()