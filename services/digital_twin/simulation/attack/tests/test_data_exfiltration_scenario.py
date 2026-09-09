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
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.simulation.attack.scenarios.data_exfiltration_scenario import DataExfiltrationScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_data_exfiltration_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 78: SCN-EXFIL-001 DATA EXFILTRATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()
    performance_state_engine.clear()

    scenario = DataExfiltrationScenario(
        source_device="CLIENT-01",
        target_device="EXTERNAL-SIMULATED-ENDPOINT",
        target_port=443,
        total_chunks=250,
        chunk_size_bytes=1460,
        duration_seconds=6,
        seed=12345
    )

    # 1. Precondition Failure Test
    print("[1/5] Auditing Precondition Validation (Target Endpoint Missing)...")
    try:
        scenario.validate()
        assert False, "Should fail when external endpoint is not registered"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Precondition engine safely blocked execution when target was absent.")

    # 2. Provision Topology & Port 443
    print("\n[2/5] Provisioning Topology: CLIENT-01 <-> EXTERNAL-SIMULATED-ENDPOINT (Port 443 OPEN)...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    ext = NetworkDeviceModel(id="EXTERNAL-SIMULATED-ENDPOINT", hostname="EXTERNAL-C2", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.EXTERNAL, ports=[443])
    device_registry.createDevice(cli)
    device_registry.createDevice(ext)
    graph_engine.addNode(cli)
    graph_engine.addNode(ext)

    conn = NetworkConnectionModel(id="c-cli-ext", sourceDevice="CLIENT-01", destinationDevice="EXTERNAL-SIMULATED-ENDPOINT")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)

    port_service_engine.openPort("EXTERNAL-SIMULATED-ENDPOINT", 443, protocol="TCP", service_name="HTTPS")

    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: Topology linked and port 443 confirmed OPEN.")

    # 3. Traffic Generation & Egress Volume Verification
    print("\n[3/5] Generating Synthetic Asymmetric Egress Burst (250 x 1460B Chunks)...")
    events = scenario.generate_traffic_events()
    print(f"    Total Wire Packet Frames : {len(events)}")

    outbound = [e for e in events if e.direction.value == "OUTBOUND"]
    inbound  = [e for e in events if e.direction.value == "INBOUND"]
    total_out_bytes = sum(e.bytes for e in outbound)

    print(f"    Outbound Data Frames     : {len(outbound)} ({total_out_bytes} bytes)")
    print(f"    Inbound ACK Frames       : {len(inbound)} ({sum(e.bytes for e in inbound)} bytes)")

    assert len(outbound) == 250
    assert total_out_bytes == 250 * 1460  # 365,000 bytes
    assert total_out_bytes > 250000

    # Confirm twin recorded active sessions and metrics
    assert network_state_engine.getConnectionStats("CLIENT-01").active >= 1
    assert network_state_engine.getNetworkMetrics("CLIENT-01").networkUtilisation == 80.0
    print("    [PASS] Verified 365,000 bytes outbound transfer and network strain.")

    # 4. Expected Indicators Verification
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "UNUSUAL_OUTBOUND_VOLUME" in observed
    assert "UNUSUAL_DESTINATION" in observed
    assert "HIGH_TRANSFER_RATE" in observed
    assert "LONG_OUTBOUND_SESSION" in observed
    print("    [PASS] All 4 expected indicators matched cleanly.")

    # 5. Full End-to-End Execution, Severity & Healing
    print("\n[5/5] Executing Full Scenario Lifecycle via execute()...")
    scenario_fresh = DataExfiltrationScenario(
        source_device="CLIENT-01",
        target_device="EXTERNAL-SIMULATED-ENDPOINT",
        target_port=443,
        total_chunks=250,
        chunk_size_bytes=1460,
        duration_seconds=6,
        seed=12345
    )
    result = scenario_fresh.execute()

    print(f"    Final State        : {result.finalState}")
    print(f"    Total Wire Frames  : {result.eventsGenerated}")
    print(f"    Total Bytes        : {result.bytesGenerated}B")
    print(f"    Risk Score         : {result.riskScore} ({result.riskLevel})")
    print(f"    Alerts Generated   : {result.alertsGenerated}")
    print(f"    Recovery Verified  : {result.recoveryVerified}")

    assert result.finalState == "COMPLETED"
    assert result.riskLevel == "CRITICAL"
    assert result.riskScore >= 75.0
    assert result.recoveryVerified is True

    # Confirm twin state healed
    assert network_state_engine.getConnectionStats("CLIENT-01").active == 0
    assert performance_state_engine.getPerformanceState("CLIENT-01").cpu == 25.0
    assert network_state_engine.getNetworkMetrics("CLIENT-01").networkUtilisation == 20.0
    print("    [PASS] Scenario reached COMPLETED and twin state verified restored.")

    print("\n" + "=" * 80)
    print("       ALL DAY 78 SCN-EXFIL-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_data_exfiltration_suite()