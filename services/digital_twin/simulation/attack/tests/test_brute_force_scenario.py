import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel
from packages.shared_types.src.attack_scenario import AttackScenarioStateEnum, AttackScenarioSeverityEnum

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.simulation.attack.scenarios.brute_force_scenario import BruteForceAttackScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_brute_force_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 73: SCN-BRUTEFORCE-001 AUTHENTICATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()

    scenario = BruteForceAttackScenario(
        source_device="CLIENT-01",
        target_device="SERVER-01",
        target_account="admin",
        total_attempts=12,
        succeed_at_end=True,
        seed=12345
    )

    # 1. Precondition Enforcement Test
    print("[1/5] Auditing Precondition Validation (Missing Target / Service)...")
    try:
        scenario.validate()
        assert False, "Should fail when SSH service and target do not exist"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Precondition engine safely blocked execution when SSH was not configured.")

    # 2. Provision Topology & Service
    print("\n[2/5] Provisioning Topology with SSH on SERVER-01...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    srv = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    device_registry.createDevice(cli)
    device_registry.createDevice(srv)
    graph_engine.addNode(cli)
    graph_engine.addNode(srv)

    conn = NetworkConnectionModel(id="c-cli-srv", sourceDevice="CLIENT-01", destinationDevice="SERVER-01")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)

    port_service_engine.openPort("SERVER-01", 22, protocol="TCP", service_name="SSH")

    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: SSH service and port 22 verified on SERVER-01.")

    # 3. Traffic Generation & Synthetic Flow Audit
    print("\n[3/5] Generating Synthetic Repeated Auth Flow (11 Failures -> 1 Success)...")
    events = scenario.generate_traffic_events()
    print(f"    Total Wire Packets Generated : {len(events)} (12 Client attempts + 12 Server responses)")
    print(f"    Auth Event Audit Ledger Rows : {len(scenario.auth_audit_log)}")

    assert len(events) == 24
    assert len(scenario.auth_audit_log) == 24

    # Audit that no weaponized payloads exist
    for log_evt in scenario.auth_audit_log:
        assert log_evt.username == "admin"
        assert log_evt.details.get("password") is None, "Safety invariant: No cleartext passwords permitted"

    failures = [e for e in scenario.auth_audit_log if e.eventType.value == "AUTH_FAILURE"]
    successes = [e for e in scenario.auth_audit_log if e.eventType.value == "AUTH_SUCCESS"]
    assert len(failures) == 11
    assert len(successes) == 1
    assert successes[0].attemptNumber == 12
    print("    [PASS] Verified 11 consecutive AUTH_FAILURE events followed by 1 terminal AUTH_SUCCESS.")

    # 4. Expected Indicators Verification
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "HIGH_AUTH_FAILURE_RATE" in observed
    assert "REPEATED_AUTH_FAILURES" in observed
    assert "SHORT_FAILURE_INTERVAL" in observed
    assert "UNUSUAL_AUTH_PATTERN" in observed
    print("    [PASS] All 4 expected indicators matched cleanly.")

    # 5. End-to-End Execution, Severity & Healing
    print("\n[5/5] Executing Full Lifecycle via execute()...")
    scenario_fresh = BruteForceAttackScenario(
        source_device="CLIENT-01",
        target_device="SERVER-01",
        target_account="admin",
        total_attempts=12,
        succeed_at_end=True,
        seed=12345
    )
    result = scenario_fresh.execute()

    print(f"    Final State        : {result.finalState}")
    print(f"    Total Wire Frames  : {result.eventsGenerated}")
    print(f"    Risk Score         : {result.riskScore} ({result.riskLevel})")
    print(f"    Alerts Generated   : {result.alertsGenerated}")
    print(f"    Recovery Verified  : {result.recoveryVerified}")

    assert result.finalState == "COMPLETED"
    assert result.eventsGenerated == 24
    assert result.riskLevel == "HIGH"
    assert result.recoveryVerified is True

    # Confirm twin connection state is clear
    stats = network_state_engine.getConnectionStats("SERVER-01")
    assert stats.active == 0
    print("    [PASS] Complete scenario succeeded and twin state confirmed healed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 73 SCN-BRUTEFORCE-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_brute_force_suite()