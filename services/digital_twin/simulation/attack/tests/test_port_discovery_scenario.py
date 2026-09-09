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
from services.digital_twin.simulation.attack.scenarios.port_discovery_scenario import PortDiscoveryScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_port_discovery_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 72: SCN-PORTSCAN-001 PORT DISCOVERY AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()

    scenario = PortDiscoveryScenario(source_device="CLIENT-01", target_device="SERVER-01", seed=12345)

    # 1. Precondition Failure Test
    print("[1/5] Testing Precondition Enforcement (Missing Hosts & Links)...")
    try:
        scenario.validate()
        assert False, "Should fail when devices do not exist"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Preconditions cleanly blocked execution when hosts were absent.")

    # 2. Provision Topology
    print("\n[2/5] Provisioning Topology: CLIENT-01 <-> Switch <-> SERVER-01...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    srv = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    device_registry.createDevice(cli)
    device_registry.createDevice(srv)
    graph_engine.addNode(cli)
    graph_engine.addNode(srv)

    # Add network connection between them
    conn = NetworkConnectionModel(id="c-cli-srv", sourceDevice="CLIENT-01", destinationDevice="SERVER-01")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)

    # Open SSH on port 22
    port_service_engine.openPort("SERVER-01", 22, protocol="TCP", service_name="SSH")

    # Re-validate
    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: Hosts provisioned and topological route verified.")

    # 3. Traffic Generation & Port Responses
    print("\n[3/5] Generating Synthetic Sequential SYN Sweep (21, 22, 25, 53, 80, 443, 8080)...")
    events = scenario.generate_traffic_events()
    print(f"    Generated {len(events)} total packet frames (7 SYN probes + 7 server responses).")
    assert len(events) == 14

    syn_probes = [e for e in events if e.direction.value == "OUTBOUND"]
    server_resps = [e for e in events if e.direction.value == "INBOUND"]

    assert len(syn_probes) == 7
    assert len(server_resps) == 7

    probed_ports = [e.destinationPort for e in syn_probes]
    assert probed_ports == [21, 22, 25, 53, 80, 443, 8080]

    # Check port 22 established (OPEN) vs others RST (FAILED)
    p22_resp = next(e for e in server_resps if e.sourcePort == 22)
    assert p22_resp.tcpState.value == "ESTABLISHED"
    assert p22_resp.details.get("flag") == "SYN_ACK"

    closed_resps = [e for e in server_resps if e.sourcePort != 22]
    assert len(closed_resps) == 6
    assert all(e.tcpState.value == "FAILED" for e in closed_resps)
    assert all(e.details.get("flag") == "RST" for e in closed_resps)
    print("    [PASS] Port 22 responded with SYN_ACK; 6 closed ports responded with RST.")

    # 4. Expected Indicator Detection
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "UNUSUAL_PORT_ACTIVITY" in observed
    assert "HIGH_UNIQUE_PORT_COUNT" in observed
    assert "HIGH_FAILED_CONNECTION_RATE" in observed
    print("    [PASS] All 3 expected indicators matched: UNUSUAL_PORT_ACTIVITY, HIGH_UNIQUE_PORT_COUNT, HIGH_FAILED_CONNECTION_RATE.")

    # 5. End-to-End Execution & Recovery
    print("\n[5/5] Executing Full Scenario Lifecycle via execute()...")
    scenario_fresh = PortDiscoveryScenario(source_device="CLIENT-01", target_device="SERVER-01", seed=12345)
    res = scenario_fresh.execute()

    print(f"    Final State        : {res.finalState}")
    print(f"    Events Emitted     : {res.eventsGenerated}")
    print(f"    Risk Score         : {res.riskScore} ({res.riskLevel})")
    print(f"    Alerts Generated   : {res.alertsGenerated}")
    print(f"    Recovery Status    : {res.recoveryStatus} (Verified: {res.recoveryVerified})")

    assert res.finalState == "COMPLETED"
    assert res.eventsGenerated == 14
    assert res.riskScore == 34.0
    assert res.riskLevel == "MEDIUM"
    assert res.recoveryVerified is True

    # Confirm twin connection state is clear
    stats = network_state_engine.getConnectionStats("SERVER-01")
    assert stats.active == 0
    print("    [PASS] Scenario reached COMPLETED and Digital Twin state confirmed healed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 72 SCN-PORTSCAN-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_port_discovery_suite()