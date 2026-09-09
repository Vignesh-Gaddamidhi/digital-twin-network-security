import sys
from pathlib import Path

# Resolve workspace root reliably (parent of 'services' and 'packages')
current_dir = Path(__file__).resolve().parent
while current_dir != current_dir.parent:
    if (current_dir / "packages").exists() and (current_dir / "services").exists():
        ROOT_DIR = current_dir
        break
    current_dir = current_dir.parent
else:
    ROOT_DIR = Path(__file__).resolve().parents[5]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel
from packages.shared_types.src.preconditions import (
    PreconditionTypeEnum, PreconditionOperatorEnum, PreconditionRuleModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.simulation.attack.validation.precondition_engine import precondition_engine

def run_preconditions_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 66: PRECONDITIONS & TARGET VALIDATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()

    # 1. Device Validation Failure Check (Target Absent)
    print("[1/5] Auditing Target Device Precondition Check...")
    rule_dev = PreconditionRuleModel(
        type=PreconditionTypeEnum.DEVICE_EXISTS,
        target="server-01",
        expectedValue=True
    )
    res_dev_fail = precondition_engine.evaluate_rule(rule_dev)
    assert res_dev_fail.passed is False
    assert "does not exist" in res_dev_fail.reason
    print("    [PASS] Device absence correctly caught and reported.")

    # Provision Host
    srv = NetworkDeviceModel(id="server-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    device_registry.createDevice(srv)
    graph_engine.addNode(srv)
    res_dev_pass = precondition_engine.evaluate_rule(rule_dev)
    assert res_dev_pass.passed is True
    print("    [PASS] Device presence verified after provisioning.")

    # 2. Service Validation Check (SSH Service)
    print("\n[2/5] Auditing Service Precondition Check (SSH on server-01)...")
    rule_svc = PreconditionRuleModel(
        type=PreconditionTypeEnum.SERVICE_EXISTS,
        target="server-01",
        expectedValue="SSH"
    )
    # Fails initially because port service engine hasn't opened SSH
    res_svc_fail = precondition_engine.evaluate_rule(rule_svc)
    assert res_svc_fail.passed is False
    print("    [PASS] Unregistered service correctly caught.")

    # Register SSH on Port 22
    port_service_engine.openPort("server-01", 22, protocol="TCP", service_name="SSH")
    res_svc_pass = precondition_engine.evaluate_rule(rule_svc)
    assert res_svc_pass.passed is True
    print("    [PASS] SSH service successfully verified on server-01.")

    # 3. Port State Validation Check (Port 22 OPEN, Port 23 CLOSED)
    print("\n[3/5] Auditing Port State Preconditions (OPEN vs CLOSED)...")
    rule_p22_open = PreconditionRuleModel(
        type=PreconditionTypeEnum.PORT_STATE,
        target="server-01:22",
        expectedValue="OPEN"
    )
    rule_p23_closed = PreconditionRuleModel(
        type=PreconditionTypeEnum.PORT_STATE,
        target="server-01:23",
        expectedValue="CLOSED"
    )
    assert precondition_engine.evaluate_rule(rule_p22_open).passed is True
    assert precondition_engine.evaluate_rule(rule_p23_closed).passed is True
    print("    [PASS] Port 22 confirmed OPEN and Port 23 confirmed CLOSED.")

    # 4. Network Connection / Reachability Check
    print("\n[4/5] Auditing Network Topology Reachability Check...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    device_registry.createDevice(cli)
    graph_engine.addNode(cli)

    rule_reach = PreconditionRuleModel(
        type=PreconditionTypeEnum.NETWORK_CONNECTION,
        target="client-01:server-01",
        expectedValue=True
    )
    # Unlinked nodes fail reachability
    res_reach_fail = precondition_engine.evaluate_rule(rule_reach)
    assert res_reach_fail.passed is False
    assert "No network route exists" in res_reach_fail.reason
    print("    [PASS] Disconnected hosts correctly failed reachability check.")

    # Connect client-01 and server-01 via an edge
    conn = NetworkConnectionModel(id="c-cli-srv", sourceDevice="client-01", destinationDevice="server-01")
    connection_registry.createConnection(conn)
    graph_engine.addEdge(conn, is_bidirectional=True)
    res_reach_pass = precondition_engine.evaluate_rule(rule_reach)
    assert res_reach_pass.passed is True
    print("    [PASS] Network reachability confirmed after adding link.")

    # 5. Full Composite Scenario Precondition Report
    print("\n[5/5] Auditing Full Precondition Report Generation...")
    report = precondition_engine.validate_scenario_preconditions(
        scenario_id="SCN-BRUTEFORCE-001",
        target_device="server-01",
        rules=[rule_dev, rule_svc, rule_p22_open, rule_p23_closed, rule_reach],
        source_device="client-01"
    )

    print(f"    Scenario ID          : {report.scenarioId}")
    print(f"    Is Valid Execution   : {report.isValid}")
    print(f"    Rules Evaluated      : {report.totalRulesEvaluated}")
    print(f"    Passed Rules Count   : {report.passedRulesCount}")
    print(f"    Failed Rules Count   : {report.failedRulesCount}")
    assert report.isValid is True
    assert report.passedRulesCount == 5
    assert report.failedRulesCount == 0
    print("    [PASS] All 5 preconditions passed cleanly in composite report.")

    print("\n" + "=" * 80)
    print("       ALL DAY 66 PRECONDITION & TARGET VALIDATION TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_preconditions_suite()