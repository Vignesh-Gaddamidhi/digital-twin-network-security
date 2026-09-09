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
from services.digital_twin.simulation.attack.scenarios.dos_saturation_scenario import DosSaturationScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_dos_saturation_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 74: SCN-DOS-001 VOLUMETRIC SATURATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()
    performance_state_engine.clear()

    scenario = DosSaturationScenario(
        source_device="CLIENT-01",
        target_device="WEB-01",
        target_port=443,
        baseline_rate=100.0,
        spike_rate=800.0,
        seed=12345
    )

    # 1. Precondition Failure Test
    print("[1/5] Auditing Precondition Validation (Missing WEB-01 Host)...")
    try:
        scenario.validate()
        assert False, "Should fail when WEB-01 does not exist"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Precondition engine safely blocked execution when WEB-01 was missing.")

    # 2. Provision Topology & Open HTTPS Port
    print("\n[2/5] Provisioning Topology: CLIENT-01 <-> Switch <-> WEB-01 (Port 443 OPEN)...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    graph_engine.addNode(cli)
    graph_engine.addNode(web)

    conn = NetworkConnectionModel(id="c-cli-web", sourceDevice="CLIENT-01", destinationDevice="WEB-01")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)

    port_service_engine.openPort("WEB-01", 443, protocol="TCP", service_name="HTTPS")

    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: WEB-01 provisioned with port 443 in OPEN state.")

    # 3. Traffic Generation & Trapezoidal Spike Curve
    print("\n[3/5] Generating Synthetic Volumetric Traffic Saturation (100 -> 800 eps)...")
    events = scenario.generate_traffic_events()
    print(f"    Total Wire Packets Generated : {len(events)}")
    print(f"    Spike Max Utilisation        : {scenario.spike_metrics['maxNetworkUtilisation']}%")
    print(f"    Spike Max CPU Load           : {scenario.spike_metrics['maxCpuLoad']}%")
    print(f"    Spike Max Active Connections : {scenario.spike_metrics['maxActiveConnections']}")

    assert len(events) >= 50
    assert scenario.spike_metrics['maxNetworkUtilisation'] == 95.0
    assert scenario.spike_metrics['maxCpuLoad'] == 85.0

    # Verify degraded state on twin
    perf_degraded = performance_state_engine.getPerformanceState("WEB-01")
    net_degraded = network_state_engine.getNetworkMetrics("WEB-01")
    assert perf_degraded.cpu == 85.0
    assert net_degraded.networkUtilisation == 95.0
    print("    [PASS] Digital Twin host strain verified: CPU=85.0%, Line Utilisation=95.0%.")

    # 4. Expected Indicators Verification
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "TRAFFIC_VOLUME_SPIKE" in observed
    assert "HIGH_PACKET_RATE" in observed
    assert "HIGH_CONNECTION_RATE" in observed
    assert "HIGH_NETWORK_UTILISATION" in observed
    print("    [PASS] All 4 expected indicators matched: TRAFFIC_VOLUME_SPIKE, HIGH_PACKET_RATE, HIGH_CONNECTION_RATE, HIGH_NETWORK_UTILISATION.")

    # 5. Full End-to-End Execution & Recovery
    print("\n[5/5] Executing Full Scenario Lifecycle via execute()...")
    scenario_fresh = DosSaturationScenario(
        source_device="CLIENT-01",
        target_device="WEB-01",
        target_port=443,
        baseline_rate=100.0,
        spike_rate=800.0,
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

    # Confirm twin state healed to baseline
    healed_cpu = performance_state_engine.getPerformanceState("WEB-01").cpu
    healed_util = network_state_engine.getNetworkMetrics("WEB-01").networkUtilisation
    healed_conns = network_state_engine.getConnectionStats("WEB-01").active

    assert healed_cpu == 25.0
    assert healed_util == 20.0
    assert healed_conns == 0
    print(f"    [PASS] Digital Twin state verified healed: CPU={healed_cpu}%, Util={healed_util}%, Sockets={healed_conns}.")

    print("\n" + "=" * 80)
    print("       ALL DAY 74 SCN-DOS-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_dos_saturation_suite()