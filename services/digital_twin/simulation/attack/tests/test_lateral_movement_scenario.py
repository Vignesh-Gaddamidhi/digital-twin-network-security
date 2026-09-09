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
from services.digital_twin.simulation.attack.scenarios.lateral_movement_scenario import LateralMovementScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_lateral_movement_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 77: SCN-LATERAL-001 LATERAL MOVEMENT AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()

    scenario = LateralMovementScenario(
        source_device="CLIENT-01",
        intermediate_1="SERVER-01",
        intermediate_2="SERVER-02",
        destination_target="DB-01",
        seed=12345
    )

    # 1. Precondition Failure Test (Missing intermediate & DB hosts)
    print("[1/5] Auditing Precondition Validation (Missing Pivot Hosts)...")
    try:
        scenario.validate()
        assert False, "Should fail when multi-hop hosts are absent from registry"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Precondition engine safely blocked execution when pivot hosts were missing.")

    # 2. Provision Complete Multi-Tier Topology
    print("\n[2/5] Provisioning Multi-Tier Pivot Topology: CLIENT-01 -> SERVER-01 -> SERVER-02 -> DB-01...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    s1  = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[22])
    s2  = NetworkDeviceModel(id="SERVER-02", hostname="SERVER-02", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[445])
    db  = NetworkDeviceModel(id="DB-01",     hostname="DB-01",     type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    device_registry.createDevice(cli)
    device_registry.createDevice(s1)
    device_registry.createDevice(s2)
    device_registry.createDevice(db)

    graph_engine.addNode(cli)
    graph_engine.addNode(s1)
    graph_engine.addNode(s2)
    graph_engine.addNode(db)

    # Topological interconnects
    for c_id, src, dst in [("c1", "CLIENT-01", "SERVER-01"), ("c2", "SERVER-01", "SERVER-02"), ("c3", "SERVER-02", "DB-01")]:
        c = NetworkConnectionModel(id=c_id, sourceDevice=src, destinationDevice=dst)
        connection_registry.createConnection(c)
        graph_engine.addEdge(c, is_bidirectional=True)

    port_service_engine.openPort("SERVER-01", 22, protocol="TCP", service_name="SSH")
    port_service_engine.openPort("SERVER-02", 445, protocol="TCP", service_name="SMB")
    port_service_engine.openPort("DB-01", 5432, protocol="TCP", service_name="POSTGRESQL")

    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: All 4 devices registered and linked in graph topology.")

    # 3. Traffic Generation & Hop Progression
    print("\n[3/5] Generating Synthetic Multi-Hop Sequential Pivot Streams...")
    events = scenario.generate_traffic_events()
    print(f"    Total Wire Packet Frames : {len(events)} (3 Hops x 2 Frames)")
    assert len(events) == 6

    hops_seen = [(e.sourceDevice, e.destinationDevice, e.destinationPort) for e in events if e.direction.value == "OUTBOUND"]
    print(f"    Traversed Hops: {hops_seen}")

    assert hops_seen[0] == ("CLIENT-01", "SERVER-01", 22)
    assert hops_seen[1] == ("SERVER-01", "SERVER-02", 445)
    assert hops_seen[2] == ("SERVER-02", "DB-01", 5432)

    # Confirm twin recorded active sessions across intermediate nodes
    assert network_state_engine.getConnectionStats("SERVER-01").active >= 1
    assert network_state_engine.getConnectionStats("SERVER-02").active >= 1
    assert network_state_engine.getConnectionStats("DB-01").active >= 1
    print("    [PASS] Multi-hop path verified across SSH, SMB, and PostgreSQL listeners.")

    # 4. Expected Indicators Verification
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "UNUSUAL_DEVICE_SEQUENCE" in observed
    assert "NEW_INTERNAL_CONNECTION" in observed
    assert "MULTI_HOST_CONNECTION_PATTERN" in observed
    assert "UNUSUAL_DESTINATION" in observed
    assert "INCREASED_INTERNAL_CONNECTIONS" in observed
    print("    [PASS] All 5 expected indicators matched: UNUSUAL_DEVICE_SEQUENCE, NEW_INTERNAL_CONNECTION, MULTI_HOST_CONNECTION_PATTERN, UNUSUAL_DESTINATION, INCREASED_INTERNAL_CONNECTIONS.")

    # 5. Full End-to-End Execution & State Restoration
    print("\n[5/5] Executing Full Scenario Lifecycle via execute()...")
    scenario_fresh = LateralMovementScenario(
        source_device="CLIENT-01",
        intermediate_1="SERVER-01",
        intermediate_2="SERVER-02",
        destination_target="DB-01",
        seed=12345
    )
    result = scenario_fresh.execute()

    print(f"    Final State        : {result.finalState}")
    print(f"    Total Wire Frames  : {result.eventsGenerated}")
    print(f"    Risk Score         : {result.riskScore} ({result.riskLevel})")
    print(f"    Alerts Generated   : {result.alertsGenerated}")
    print(f"    Affected Devices   : {result.affectedDevices}")
    print(f"    Recovery Verified  : {result.recoveryVerified}")

    assert result.finalState == "COMPLETED"
    assert result.riskLevel == "HIGH"
    assert len(result.affectedDevices) == 4
    assert result.recoveryVerified is True

    # Confirm all sessions across all 4 devices are purged
    for dev in ["CLIENT-01", "SERVER-01", "SERVER-02", "DB-01"]:
        stats = network_state_engine.getConnectionStats(dev)
        assert stats.active == 0
    print("    [PASS] Complete lateral scenario succeeded and all intermediate twin sessions purged.")

    print("\n" + "=" * 80)
    print("       ALL DAY 77 SCN-LATERAL-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_lateral_movement_suite()