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
from services.digital_twin.simulation.attack.scenarios.suspicious_dns_scenario import SuspiciousDnsScenario
from services.digital_twin.simulation.attack.framework.scenario_validator import ScenarioPreconditionFailedError

def run_suspicious_dns_suite():
    print("=" * 80)
    print("       WEEK 11 - DAY 75: SCN-DNS-001 SUSPICIOUS DNS BEHAVIOUR AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()
    performance_state_engine.clear()

    scenario = SuspiciousDnsScenario(
        source_device="CLIENT-01",
        target_device="DNS-01",
        target_port=53,
        total_queries=60,
        seed=12345
    )

    # 1. Precondition Failure Test
    print("[1/5] Auditing Precondition Validation (Target DNS-01 Absent)...")
    try:
        scenario.validate()
        assert False, "Should fail when DNS-01 does not exist"
    except ScenarioPreconditionFailedError:
        assert scenario.state_machine.current_state == AttackScenarioStateEnum.FAILED
        print("    [PASS] Precondition engine safely blocked execution when DNS-01 was missing.")

    # 2. Provision Topology & Port 53
    print("\n[2/5] Provisioning Topology: CLIENT-01 <-> Switch <-> DNS-01 (Port 53 OPEN)...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    dns = NetworkDeviceModel(id="DNS-01", hostname="DNS-01", type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])
    device_registry.createDevice(cli)
    device_registry.createDevice(dns)
    graph_engine.addNode(cli)
    graph_engine.addNode(dns)

    conn = NetworkConnectionModel(id="c-cli-dns", sourceDevice="CLIENT-01", destinationDevice="DNS-01")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)

    port_service_engine.openPort("DNS-01", 53, protocol="UDP", service_name="DNS")

    valid = scenario.validate()
    assert valid is True
    assert scenario.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: DNS-01 provisioned with UDP port 53 OPEN.")

    # 3. Traffic Generation & Protocol Invariant Audit
    print("\n[3/5] Generating Synthetic DNS Traffic Streams (High Frequency & TXT Clustering)...")
    events = scenario.generate_traffic_events()
    print(f"    Total DNS Query Frames Generated : {len(events)}")
    assert len(events) == 60

    # Invariant: All domain queries must reside within safe .test zone
    for evt in events:
        domain = evt.details.get("dns_domain", "")
        assert domain.endswith(".test"), f"Safety invariant violation: {domain} does not end in .test"

    txt_queries = [e for e in events if e.details.get("dns_record_type") == "TXT"]
    repeated_queries = [e for e in events if e.details.get("dns_domain") == "service.test"]

    print(f"    TXT Record Queries (Tunneling Pattern) : {len(txt_queries)} ({len(txt_queries)/len(events)*100:.1f}%)")
    print(f"    Repeated Queries for 'service.test'     : {len(repeated_queries)}")
    assert len(txt_queries) == 25
    assert len(repeated_queries) == 20
    print("    [PASS] Traffic pattern adheres to .test safety constraints and tunneling patterns.")

    # 4. Expected Indicators Verification
    print("\n[4/5] Evaluating Expected Security Indicators...")
    observed = scenario.evaluate_indicators(events)
    print(f"    Observed Indicators: {observed}")

    assert "UNUSUAL_DNS_FREQUENCY" in observed
    assert "UNUSUAL_DNS_QUERY_TYPE" in observed
    assert "REPEATED_DNS_REQUESTS" in observed
    assert "UNUSUAL_DNS_DISTRIBUTION" in observed
    print("    [PASS] All 4 expected indicators matched: UNUSUAL_DNS_FREQUENCY, UNUSUAL_DNS_QUERY_TYPE, REPEATED_DNS_REQUESTS, UNUSUAL_DNS_DISTRIBUTION.")

    # 5. Full End-to-End Execution & Recovery
    print("\n[5/5] Executing Full Scenario Lifecycle via execute()...")
    scenario_fresh = SuspiciousDnsScenario(
        source_device="CLIENT-01",
        target_device="DNS-01",
        target_port=53,
        total_queries=60,
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
    assert result.riskScore == 36.3
    assert result.riskLevel == "MEDIUM"
    assert result.recoveryVerified is True

    # Confirm twin state healed
    healed_cpu = performance_state_engine.getPerformanceState("DNS-01").cpu
    healed_util = network_state_engine.getNetworkMetrics("DNS-01").networkUtilisation
    assert healed_cpu <= 25.0
    assert healed_util <= 20.0
    print(f"    [PASS] DNS-01 confirmed healed: CPU={healed_cpu}%, Util={healed_util}%.")

    print("\n" + "=" * 80)
    print("       ALL DAY 75 SCN-DNS-001 TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_suspicious_dns_suite()