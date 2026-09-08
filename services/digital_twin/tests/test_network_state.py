import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.network_state import (
    ActiveConnectionSessionModel, SessionStateEnum, DeviceNetworkMetricsModel
)
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.firewall import FirewallRuleModel, NetworkZoneTypeEnum, FirewallActionEnum

from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.state.network_state_engine import (
    network_state_engine, ConnectionAlreadyExistsError, ConnectionSessionNotFoundError
)
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.topology.reachability_engine import reachability_engine

def run_network_state_suite():
    print("=" * 80)
    print("       WEEK 7 - DAY 46: NETWORK UTILISATION & CONNECTION STATE AUDIT")
    print("=" * 80 + "\n")

    # Clear runtime states
    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    firewall_engine.clear()
    network_state_engine.clear()

    # 1. Provision Canonical Topology: Client -> Web Server -> Database Server
    print("[1/5] Provisioning Infrastructure (CLIENT-01, WEB-01, DB-01)...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    for d in [cli, web, db]:
        device_registry.createDevice(d)
        graph_engine.addNode(d)

    # Allow firewall policies
    firewall_engine.addRule(FirewallRuleModel(id="r1", sourceZone=NetworkZoneTypeEnum.INTERNAL, destinationZone=NetworkZoneTypeEnum.DMZ, protocol="TCP", destinationPort=443, action=FirewallActionEnum.ALLOW))
    firewall_engine.addRule(FirewallRuleModel(id="r2", sourceZone=NetworkZoneTypeEnum.DMZ, destinationZone=NetworkZoneTypeEnum.INTERNAL, protocol="TCP", destinationPort=5432, action=FirewallActionEnum.ALLOW))

    # Add structural edges
    c1 = NetworkConnectionModel(id="c-cli-web", sourceDevice="client-01", destinationDevice="web-01", protocol=ProtocolEnum.TCP, destinationPort=443)
    c2 = NetworkConnectionModel(id="c-web-db", sourceDevice="web-01", destinationDevice="db-01", protocol=ProtocolEnum.TCP, destinationPort=5432)
    connection_registry.createConnection(c1)
    connection_registry.createConnection(c2)
    graph_engine.addEdge(c1, is_bidirectional=True)
    graph_engine.addEdge(c2, is_bidirectional=True)
    print("    [PASS] Physical and logical baseline provisioned.")

    # 2. Network Utilisation Tracking
    print("\n[2/5] Testing Network Utilisation & Volume Tracking on WEB-01...")
    metrics = network_state_engine.updateNetworkMetrics(
        device_id="web-01",
        network_utilisation=63.0,
        bytes_sent=1500000,
        bytes_received=4200000,
        packets_sent=1200,
        packets_received=3500
    )
    assert metrics.networkUtilisation == 63.0
    assert metrics.bytesSent == 1500000
    assert metrics.bytesReceived == 4200000
    assert metrics.packetsSent == 1200
    assert metrics.packetsReceived == 3500
    print(f"    [PASS] Recorded: Utilisation={metrics.networkUtilisation}%, BytesIn={metrics.bytesReceived}, PacketsIn={metrics.packetsReceived}")

    # 3. Connection Session State Lifecycle (Create, Close, Fail)
    print("\n[3/5] Testing Connection Session Lifecycle (ACTIVE -> CLOSED / FAILED)...")
    sess1 = ActiveConnectionSessionModel(
        id="conn-101",
        source="client-01",
        destination="web-01",
        protocol="TCP",
        sourcePort=52000,
        destinationPort=443,
        status=SessionStateEnum.ACTIVE
    )
    created = network_state_engine.createConnectionState(sess1)
    assert created.id == "conn-101"
    assert created.status == SessionStateEnum.ACTIVE
    print("    [PASS] Created session conn-101 (client-01:52000 -> web-01:443 [ACTIVE]).")

    # Close session
    closed = network_state_engine.closeConnection("conn-101")
    assert closed.status == SessionStateEnum.CLOSED
    print("    [PASS] Gracefully closed session conn-101.")

    # Create and Fail another session
    sess2 = ActiveConnectionSessionModel(
        id="conn-102",
        source="web-01",
        destination="db-01",
        protocol="TCP",
        sourcePort=48000,
        destinationPort=5432,
        status=SessionStateEnum.ACTIVE
    )
    network_state_engine.createConnectionState(sess2)
    failed = network_state_engine.failConnection("conn-102")
    assert failed.status == SessionStateEnum.FAILED
    print("    [PASS] Marked session conn-102 as FAILED.")

    # 4. Connection Statistics Counters
    print("\n[4/5] Auditing Device Connection Counters...")
    web_stats = network_state_engine.getConnectionStats("web-01")
    print(f"    WEB-01 Connection Stats: Active={web_stats.active}, Closed={web_stats.closed}, Failed={web_stats.failed}, Total={web_stats.total}")
    assert web_stats.closed == 1
    assert web_stats.failed == 1
    assert web_stats.total == 2
    print("    [PASS] Connection statistics accurately aggregate multi-session metrics.")

    # 5. State-Aware Edge Dynamics (Web -> DB marked FAILED blocks reachability)
    print("\n[5/5] Testing State-Aware Graph Reachability (Failed Edge Dynamics)...")
    # Reachability Client -> DB via Web: Should be unreachable since conn-102 (web -> db) is FAILED
    reach_db = reachability_engine.isReachable("client-01", "db-01", protocol="TCP", destination_port=5432)
    assert reach_db.is_reachable is False
    print(f"    Client -> DB Reachability after Web->DB failure: {reach_db.is_reachable} (Reason: {reach_db.blocking_reason})")
    assert "is BLOCKED" in reach_db.blocking_reason
    print("    [PASS] Structural graph preserved while operational failure blocks reachability.")

    # 6. Rejection & Boundary Tests
    print("\n[Bonus] Testing Boundary Rejections (Unknown Devices, Duplicate Sessions, Invalid Enums)...")
    
    # Unknown device
    try:
        network_state_engine.createConnectionState(ActiveConnectionSessionModel(
            id="conn-bad-dev", source="ghost-pc", destination="web-01", sourcePort=5000, destinationPort=443
        ))
        assert False
    except DeviceNotFoundError:
        print("    [PASS] Rejected unknown device reference.")

    # Duplicate session
    try:
        network_state_engine.createConnectionState(sess1)
        assert False
    except ConnectionAlreadyExistsError:
        print("    [PASS] Rejected duplicate session ID.")

    # Invalid port
    try:
        ActiveConnectionSessionModel(
            id="conn-bad-port", source="client-01", destination="web-01", sourcePort=5000, destinationPort=99999
        )
        assert False
    except ValidationError:
        print("    [PASS] Rejected invalid port (>65535).")

    # Invalid protocol
    try:
        ActiveConnectionSessionModel(
            id="conn-bad-proto", source="client-01", destination="web-01", protocol="WARP_SPEED", sourcePort=5000, destinationPort=443
        )
        assert False
    except ValidationError:
        print("    [PASS] Rejected invalid protocol.")

    print("\n" + "=" * 80)
    print("       ALL DAY 46 NETWORK & CONNECTION STATE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_network_state_suite()