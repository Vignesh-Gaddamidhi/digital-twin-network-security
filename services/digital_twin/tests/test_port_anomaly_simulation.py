import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.port_anomaly import (
    PortAnomalyProfile, PortProbeMetric, PortAnomalyRunResult, PortStateMutationConfig
)
from packages.shared_types.src.port_service_state import PortStateEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.simulation.generators.port_anomaly_engine import port_anomaly_engine

def run_port_anomaly_suite():
    print("=" * 80)
    print("       WEEK 9 - DAY 61: PORT ANOMALY SIMULATION & MUTATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    port_service_engine.clear()

    # 1. Initialize Canonical Web Server with Baseline Ports 80 and 443
    print("[1/4] Provisioning WEB-01 with baseline listening ports 80, 443...")
    from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    device_registry.createDevice(web)
    port_service_engine.openPort("web-01", 80, service_name="HTTP")
    port_service_engine.openPort("web-01", 443, service_name="HTTPS")
    print("    [PASS] Baseline ports 80, 443 OPEN on WEB-01.")

    # 2. Configure Profile: Normal 443=100, 80=40, plus sweep on 21, 22=200, 25, 53, 110, 8080, 8443
    print("\n[2/4] Executing Port Anomaly Profile (Normal vs Anomaly Sweep on 21, 22, 25, 53, 80, 110, 443, 8080, 8443)...")
    profile = PortAnomalyProfile(
        name="Day61-Port-Distribution-Sweep",
        affectedDevice="client-01",
        targetDevice="web-01",
        baselinePorts=[80, 443],
        probedPorts=[21, 22, 25, 53, 80, 110, 443, 8080, 8443],
        portAttemptWeights={
            443: 100,
            80: 40,
            22: 200,
            21: 15,
            25: 15,
            53: 15,
            110: 15,
            8080: 25,
            8443: 20
        },
        mutatePort=PortStateMutationConfig(
            port=8080,
            newState="OPEN",
            serviceName="alt-http",
            reason="Backdoor listener opened during simulated attack"
        )
    )

    result = port_anomaly_engine.runPortAnomalyScenario(profile)

    print(f"    Total Probe Attempts      : {result.totalAttempts}")
    print(f"    Unusual Ports Contacted   : {result.unusualPortsDetected}")
    print(f"    State Mutated Flag        : {result.stateMutated}")
    print(f"    Mutated Port Details      : {result.mutatedPortDetails}")

    # Core Assertions
    assert result.totalAttempts == (100 + 40 + 200 + 15 + 15 + 15 + 15 + 25 + 20) # 445 total attempts
    assert 22 in result.unusualPortsDetected
    assert 8080 in result.unusualPortsDetected
    assert result.stateMutated is True
    print("    [PASS] Port anomaly sweep generated accurately.")

    # 3. Verify Specific Port Behavior (Successful vs Failed)
    print("\n[3/4] Auditing Port Attempt Counts & Success/Failure Ratios...")
    metrics_by_port = {m.destinationPort: m for m in result.portMetrics}

    p443 = metrics_by_port[443]
    p80 = metrics_by_port[80]
    p22 = metrics_by_port[22]
    p21 = metrics_by_port[21]

    print(f"    Port 443 (HTTPS) : Attempts={p443.attemptCount}, Success={p443.successfulConnections}, Failed={p443.failedConnections}, State={p443.portState}")
    print(f"    Port  80 (HTTP)  : Attempts={p80.attemptCount}, Success={p80.successfulConnections}, Failed={p80.failedConnections}, State={p80.portState}")
    print(f"    Port  22 (SSH)   : Attempts={p22.attemptCount}, Success={p22.successfulConnections}, Failed={p22.failedConnections}, State={p22.portState}")
    print(f"    Port  21 (FTP)   : Attempts={p21.attemptCount}, Success={p21.successfulConnections}, Failed={p21.failedConnections}, State={p21.portState}")

    assert p443.attemptCount == 100 and p443.successfulConnections == 100 and p443.failedConnections == 0
    assert p80.attemptCount == 40 and p80.successfulConnections == 40 and p80.failedConnections == 0
    assert p22.attemptCount == 200 and p22.successfulConnections == 0 and p22.failedConnections == 200
    assert p21.attemptCount == 15 and p21.successfulConnections == 0 and p21.failedConnections == 15
    print("    [PASS] Port metrics accurately capture successful baseline versus rejected probes.")

    # 4. Verify Digital Twin State Engine Mutation (Port 8080 OPEN)
    print("\n[4/4] Verifying Dynamic Port State Integration (8080 -> OPEN on WEB-01)...")
    p8080 = port_service_engine.getPort("web-01", 8080)
    print(f"    WEB-01 Port 8080 -> State: {p8080.state.value}, Service: {p8080.service}")
    assert p8080.state == PortStateEnum.OPEN
    assert p8080.service == "alt-http"

    # Verify device registry reflection
    dev_web = device_registry.getDevice("web-01")
    assert 8080 in dev_web.ports

    # Verify state change audit events
    audit_events = port_service_engine.getAuditEvents("web-01")
    recent_audit = audit_events[-1]
    print(f"    Audit Event -> Type: {recent_audit.eventType}, Target: {recent_audit.target}, State: {recent_audit.newState}, Reason: '{recent_audit.reason}'")
    assert recent_audit.eventType == "PORT_OPENED"
    assert recent_audit.target == "8080"
    assert recent_audit.newState == "OPEN"
    print("    [PASS] Digital Twin attack surface dynamically updated and audited.")

    print("\n" + "=" * 80)
    print("       ALL DAY 61 PORT ANOMALY SIMULATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_port_anomaly_suite()