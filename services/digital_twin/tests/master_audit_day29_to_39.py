import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum,
    NetworkInterfaceConfig, RouteEntryModel
)
from packages.shared_types.src.topology import (
    NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
)
from packages.shared_types.src.switch import PortStatusEnum
from packages.shared_types.src.service_dependency import (
    ServiceDependencyModel, DependencyTypeEnum
)
from packages.shared_types.src.firewall import (
    FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum
)
from packages.shared_types.src.graph import GraphNodeModel, GraphEdgeModel

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.devices.device_configuration_engine import config_engine
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.routing_engine import routing_engine
from services.digital_twin.core.topology.switch_engine import switch_engine
from services.digital_twin.core.topology.service_dependency_engine import service_dependency_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.topology.topology_engine_v2 import topology_engine
from services.digital_twin.core.topology.zone_engine import zone_engine
from services.digital_twin.core.topology.reachability_engine import reachability_engine

def run_master_verification():
    print("=" * 80)
    print("      DIGITAL TWIN MASTER INTEGRATION AUDIT (DAYS 29 - 39)")
    print("=" * 80 + "\n")

    # Reset in-memory registries
    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    firewall_engine.clear()
    zone_engine.clear()
    service_dependency_engine.clear()
    config_engine.clearHistory()

    # --- DAY 29: DEVICE REGISTRY ---
    print("[Day 29] Device Registry CRUD & Identity Validation...")
    server = NetworkDeviceModel(
        id="srv-web-01", hostname="web-01", type=DeviceTypeEnum.SERVER,
        ipAddresses=["192.168.10.10"], networkZone=NetworkZoneEnum.DMZ, ports=[80, 443]
    )
    device_registry.createDevice(server)
    assert device_registry.getDevice("srv-web-01") is not None
    print("  [PASS] Device creation and query verified.")

    # --- DAY 30: DEVICE CONFIGURATION ENGINE ---
    print("[Day 30] Device Dynamic Configuration & History Ledger...")
    config_engine.openPort("srv-web-01", 8443, reason="Open Admin Port")
    updated_srv = device_registry.getDevice("srv-web-01")
    assert 8443 in updated_srv.ports
    history = config_engine.getConfigurationHistory("srv-web-01")
    assert len(history) >= 1
    assert history[-1].action == "OPEN_PORT"
    print("  [PASS] Port opened and recorded in audit history.")

    # --- DAY 31: CONNECTION REGISTRY ---
    print("[Day 31] Connection Registry & Relational Constraints...")
    rtr = NetworkDeviceModel(
        id="rtr-gw-01", hostname="rtr-01", type=DeviceTypeEnum.ROUTER,
        ipAddresses=["192.168.10.1"], networkZone=NetworkZoneEnum.EXTERNAL
    )
    device_registry.createDevice(rtr)
    conn = NetworkConnectionModel(
        id="c-rtr-srv", sourceDevice="rtr-gw-01", destinationDevice="srv-web-01",
        connectionType=ConnectionTypeEnum.NETWORK, protocol=ProtocolEnum.TCP, destinationPort=443
    )
    connection_registry.createConnection(conn)
    assert connection_registry.getConnection("c-rtr-srv") is not None
    print("  [PASS] Connection registered and bound to endpoints.")

    # --- DAY 32: ROUTING ENGINE (LPM) ---
    print("[Day 32] Layer 3 Longest-Prefix Matching...")
    routing_engine.addRoute("rtr-gw-01", RouteEntryModel(destination="192.168.10.0/24", nextHop="DIRECT", interface="eth0", metric=1))
    routing_engine.addRoute("rtr-gw-01", RouteEntryModel(destination="0.0.0.0/0", nextHop="203.0.113.1", interface="wan0", metric=10))
    lpm_direct = routing_engine.findRoute("rtr-gw-01", "192.168.10.10")
    lpm_default = routing_engine.findRoute("rtr-gw-01", "8.8.8.8")
    assert lpm_direct.is_direct is True
    assert lpm_default.next_hop == "203.0.113.1"
    print("  [PASS] LPM prioritized /24 direct subnet over /0 default route.")

    # --- DAY 33: SWITCH ENGINE & CAM TABLE ---
    print("[Day 33] Layer 2 Switch Engine & CAM Table...")
    sw = NetworkDeviceModel(id="sw-core-01", hostname="sw-01", type=DeviceTypeEnum.SWITCH)
    device_registry.createDevice(sw)
    switch_engine.connectDeviceToSwitch("sw-core-01", 1, "srv-web-01", "AA:BB:CC:DD:10:10")
    cam = switch_engine.getMacTable("sw-core-01")
    assert len(cam) >= 1
    assert cam[0].mac_address == "AA:BB:CC:DD:10:10"
    print("  [PASS] Switch port connected and CAM table updated.")

    # --- DAY 34: SERVERS, CLIENTS & SERVICE DEPENDENCIES ---
    print("[Day 34] Multi-Tier Service Dependencies...")
    db = NetworkDeviceModel(
        id="srv-db-01", hostname="db-01", type=DeviceTypeEnum.DATABASE,
        ipAddresses=["192.168.20.20"], networkZone=NetworkZoneEnum.INTERNAL, ports=[5432]
    )
    device_registry.createDevice(db)
    dep = service_dependency_engine.registerDependency(ServiceDependencyModel(
        id="dep-web-db", source_device_id="srv-web-01", target_device_id="srv-db-01",
        target_service_name="PostgreSQL", target_port=5432, dependency_type=DependencyTypeEnum.BACKEND_DATASTORE
    ))
    chain = service_dependency_engine.traceDependencyChain("srv-web-01", "srv-db-01")
    assert chain.direct_dependency is True
    print("  [PASS] Multi-tier service dependency validated.")

    # --- DAY 35: FIREWALL & NETWORK ZONES ---
    print("[Day 35] Firewall Rule Inspection & Security Boundaries...")
    firewall_engine.assignDeviceToZone("zone-dmz", "srv-web-01")
    firewall_engine.assignDeviceToZone("zone-database", "srv-db-01")
    firewall_engine.addRule(FirewallRuleModel(
        id="rule-db-allow", sourceZone=NetworkZoneTypeEnum.DMZ, destinationZone=NetworkZoneTypeEnum.DATABASE,
        protocol="TCP", destinationPort=5432, action=FirewallActionEnum.ALLOW
    ))
    insp_allow = firewall_engine.inspectTraffic("srv-web-01", "srv-db-01", "TCP", 5432)
    insp_deny = firewall_engine.inspectTraffic("srv-web-01", "srv-db-01", "TCP", 22)
    assert insp_allow.decision == FirewallActionEnum.ALLOW
    assert insp_deny.decision == FirewallActionEnum.DENY
    print("  [PASS] Firewall permitted authorized traffic and dropped unlisted ports.")

    # --- DAY 36: GRAPH ENGINE G = (V, E) ---
    print("[Day 36] Graph Engine Nodes, Edges & Adjacency...")
    graph_engine.addNode(GraphNodeModel(id="node-a", type="ROUTER", label="Node A"))
    graph_engine.addNode(GraphNodeModel(id="node-b", type="SERVER", label="Node B"))
    graph_engine.addEdge(GraphEdgeModel(id="e-ab", source="node-a", target="node-b", protocol="TCP"))
    neighbors = graph_engine.getNeighbors("node-a")
    assert "node-b" in neighbors.outbound_neighbors
    print("  [PASS] Graph engine G = (V, E) adjacency verified.")

    # --- DAY 37: TOPOLOGY ENGINE & SUMMARY SNAPSHOT ---
    print("[Day 37] Topology Engine & Snapshot Generation...")
    snapshot = topology_engine.generateTopologySnapshot()
    assert snapshot.nodes >= 4
    assert snapshot.edges >= 1
    print(f"  [PASS] Topology Snapshot: {snapshot.nodes} nodes, {snapshot.edges} edges, {snapshot.zones} zones.")

    # --- DAY 38: ZONE SEGMENTATION GRAPH ---
    print("[Day 38] Zone Segmentation Graph...")
    zone_engine.assignDeviceToZone("zone-dmz", "srv-web-01")
    zone_engine.assignDeviceToZone("zone-database", "srv-db-01")
    zg = zone_engine.buildZoneSegmentationGraph()
    assert zg.zone_count >= 4
    print("  [PASS] Macro Zone Segmentation Graph successfully constructed.")

    # --- DAY 39: REACHABILITY ENGINE ---
    print("[Day 39] Security-Constrained Reachability...")
    graph_engine.clear()
    graph_engine.addNode(GraphNodeModel(id="srv-web-01", type="SERVER", label="Web Server"))
    graph_engine.addNode(GraphNodeModel(id="srv-db-01", type="DATABASE", label="Database Server"))
    graph_engine.addEdge(GraphEdgeModel(id="c-web-db", source="srv-web-01", target="srv-db-01", protocol="TCP", weight=0.5), is_bidirectional=True)
    
    reach_allow = reachability_engine.isReachable("srv-web-01", "srv-db-01", protocol="TCP", destination_port=5432)
    assert reach_allow.is_reachable is True

    reach_deny_port = reachability_engine.isReachable("srv-web-01", "srv-db-01", protocol="TCP", destination_port=9999)
    assert reach_deny_port.is_reachable is False

    print("  [PASS] Reachability confirmed for open port and rejected for closed port.")

    print("\n" + "=" * 80)
    print("  ALL SYSTEMS OPERATIONAL: DAYS 29 THROUGH 39 FULLY VERIFIED")
    print("=" * 80)

if __name__ == "__main__":
    run_master_verification()