import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel
from packages.shared_types.src.attack_scenario import AttackScenarioStateEnum

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.simulation.attack.scenarios.beaconing_scenario import BeaconingAttackScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_beaconing_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 76: SCN-BEACON-001 C2 BEACONING PATTERN AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()

    scenario = BeaconingAttackScenario(
        source_device="CLIENT-01",
        target_device="SERVER-01",
        target_port=443,
        interval_seconds=1.0,
        total_beacons=10,
        jitter_ratio=0.05,
        seed=12345
    )

    # 1. Precondition Failure Test
    print("[1/5] Auditing Precondition Validation (Missing Endpoints / Port)...")
    try:
        scenario.validate()
        assert False, "Should fail when SERVER-01 and port 443 do not exist"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Precondition engine safely blocked execution when endpoints were missing.")

    # 2. Provision Topology & Port 443
    print("\n[2/5] Provisioning Topology: CLIENT-01 <-> Switch <-> SERVER-01 (Port 443 OPEN)...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    srv = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[443])
    device_registry.createDevice(cli)
    device_registry.createDevice(srv)
    graph_engine.addNode(cli)
    graph_engine.addNode(srv)

    conn = NetworkConnectionModel(id="c-cli-srv", sourceDevice="CLIENT-01", destinationDevice="SERVER-01")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)

    port_service_engine.openPort("SERVER-01", 443, protocol="TCP", service_name="HTTPS")

    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: CLIENT-01 and SERVER-01 online with port 443 OPEN.")

    # 3. Traffic Generation & Deterministic Regularity
    print("\n[3/5] Generating Synthetic C2 Heartbeat Beacons (1.0s interval ± 5% jitter)...")
    events = scenario.generate_traffic_events()
    print(f"    Total Packet Frames Emitted : {len(events)} (10 Outbound heartbeats + 10 Inbound ACKs)")
    assert len(events) == 20

    outbound_beacons = [e for e in events if e.direction.value == "OUTBOUND"]
    assert len(outbound_beacons) == 10
    assert all(e.destinationPort == 443 for e in outbound_beacons)

    # Verify that sessions were recorded in twin
    stats_mid = network_state_engine.getConnectionStats("SERVER-01")
    assert stats_mid.active == 10
    print("    [PASS] Verified 10 periodic HTTPS heartbeat frames with active twin session allocation.")

    # 4. Expected Indicators Verification
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "PERIODIC_TRAFFIC" in observed
    assert "REPEATED_DESTINATION" in observed
    assert "REGULAR_TIME_INTERVAL" in observed
    assert "UNUSUAL_CONNECTION_FREQUENCY" in observed
    print("    [PASS] All 4 expected indicators matched: PERIODIC_TRAFFIC, REPEATED_DESTINATION, REGULAR_TIME_INTERVAL, UNUSUAL_CONNECTION_FREQUENCY.")

    # 5. Full End-to-End Execution & Recovery
    print("\n[5/5] Executing Full Scenario Lifecycle via execute()...")
    scenario_fresh = BeaconingAttackScenario(
        source_device="CLIENT-01",
        target_device="SERVER-01",
        target_port=443,
        interval_seconds=1.0,
        total_beacons=10,
        jitter_ratio=0.05,
        seed=12345
    )
    result = scenario_fresh.execute()

    print(f"    Final State        : {result.finalState}")
    print(f"    Events Emitted     : {result.eventsGenerated}")
    print(f"    Total Bytes        : {result.bytesGenerated}B")
    print(f"    Risk Score         : {result.riskScore} ({result.riskLevel})")
    print(f"    Alerts Generated   : {result.alertsGenerated}")
    print(f"    Recovery Verified  : {result.recoveryVerified}")

    assert result.finalState == "COMPLETED"
    assert result.riskLevel == "HIGH"
    assert result.recoveryVerified is True

    # Confirm twin state healed and sockets closed
    stats_post = network_state_engine.getConnectionStats("SERVER-01")
    assert stats_post.active == 0
    print(f"    [PASS] Twin state confirmed healed: active sockets={stats_post.active}.")

    print("\n" + "=" * 80)
    print("       ALL DAY 76 SCN-BEACON-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_beaconing_suite()