import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.network_state import ActiveConnectionSessionModel, SessionStateEnum
from packages.shared_types.src.attack_recovery import (
    RecoveryStrategyEnum, ScenarioRecoveryPlan, DeviceRecoveryResult
)
from packages.shared_types.src.port_service_state import PortStateEnum

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.simulation.attack.recovery.recovery_engine import recovery_engine

def run_recovery_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 70: ATTACK SCENARIO RECOVERY & HEALING AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    network_state_engine.clear()
    performance_state_engine.clear()
    port_service_engine.clear()

    # 1. Provision Canonical Devices (Client and Web Server)
    print("[1/5] Provisioning CLIENT-01 and WEB-01 Hosts...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    port_service_engine.openPort("web-01", 80, service_name="HTTP")
    port_service_engine.openPort("web-01", 443, service_name="HTTPS")
    print("    [PASS] Provisioned client-01 and web-01 with baseline ports 80 and 443.")

    # 2. Inject Abnormal Attack Degradation (Simulating Active Exploit Impact)
    print("\n[2/5] Injecting Simulated Attack State (High CPU, Line Saturation, Flooded Sockets, Rogue Port)...")
    performance_state_engine.updateCpu("web-01", 92.5, source="SIM_ATTACK")
    network_state_engine.updateNetworkMetrics(device_id="web-01", network_utilisation=96.0, bytes_sent=10000, bytes_received=500000)
    port_service_engine.openPort("web-01", 8080, service_name="alt-http", reason="Simulated rogue backdoor")

    for i in range(15):
        sess = ActiveConnectionSessionModel(
            id=f"attack-flood-sess-{i}",
            source="client-01",
            destination="web-01",
            protocol="TCP",
            sourcePort=50000 + i,
            destinationPort=8080,
            status=SessionStateEnum.ACTIVE
        )
        network_state_engine.createConnectionState(sess)

    # Verify degraded state exists
    assert performance_state_engine.getPerformanceState("web-01").cpu > 90.0
    assert network_state_engine.getNetworkMetrics("web-01").networkUtilisation > 90.0
    assert port_service_engine.getPort("web-01", 8080).state == PortStateEnum.OPEN
    assert network_state_engine.getConnectionStats("web-01").active == 15
    print("    [PASS] Degradation injected: CPU=92.5%, Util=96.0%, Active Sockets=15, Port 8080 OPEN.")

    # 3. Configure and Execute Recovery Plan
    print("\n[3/5] Executing Recovery Plan (RESTORE_BASELINE)...")
    plan = ScenarioRecoveryPlan(
        scenarioId="SCN-RECOVERY-TEST-001",
        strategy=RecoveryStrategyEnum.RESTORE_BASELINE,
        durationSeconds=2.0,
        affectedDevices=["web-01"],
        restoreTraffic=True,
        restoreConnections=True,
        revertPortMutations=True,
        verificationRequired=True
    )

    report = recovery_engine.execute_recovery(plan, mutated_ports={"web-01": [8080]})
    print(f"    Total Closed Connections : {report.totalConnectionsClosed}")
    print(f"    Total Reverted Ports     : {report.totalPortsReverted}")
    print(f"    Verification Result      : {report.verified}")

    assert report.totalConnectionsClosed == 15
    assert report.totalPortsReverted == 1
    assert report.verified is True
    print("    [PASS] Recovery engine closed 15 sessions and reverted port 8080.")

    # 4. Audit Digital Twin Post-Healing State
    print("\n[4/5] Auditing Digital Twin Healed Posture...")
    perf_healed = performance_state_engine.getPerformanceState("web-01")
    net_healed = network_state_engine.getNetworkMetrics("web-01")
    port_8080 = port_service_engine.getPort("web-01", 8080)
    sess_stats = network_state_engine.getConnectionStats("web-01")

    print(f"    Healed CPU               : {perf_healed.cpu}% (Expected <= 25.0%)")
    print(f"    Healed Utilisation       : {net_healed.networkUtilisation}% (Expected <= 20.0%)")
    print(f"    Rogue Port 8080 State    : {port_8080.state.value} (Expected CLOSED)")
    print(f"    Active Sessions Remaining: {sess_stats.active} (Expected 0)")

    assert perf_healed.cpu == 25.0
    assert net_healed.networkUtilisation == 20.0
    assert port_8080.state == PortStateEnum.CLOSED
    assert sess_stats.active == 0
    print("    [PASS] Digital Twin confirmed completely healed to normal baseline.")

    # 5. Test Stand-Alone Verification Subsystem
    print("\n[5/5] Auditing Standalone Verification Subsystem...")
    verified, details = recovery_engine.execute_recovery(plan, mutated_ports={"web-01": [8080]}).verified, report.verificationDetails
    assert verified is True
    assert details["web-01"]["healthy"] is True
    print("    [PASS] RecoveryVerifier confirmed zero lingering anomalies.")

    print("\n" + "=" * 80)
    print("       ALL DAY 70 RECOVERY FRAMEWORK TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_recovery_suite()