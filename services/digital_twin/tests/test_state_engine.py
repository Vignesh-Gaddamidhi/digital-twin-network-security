import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.device_state import (
    ComprehensiveDeviceStateModel, PerformanceStateModel, NetworkTelemetryStateModel,
    PortStateEntry, ServiceRuntimeEntry, SecurityStateBlockModel,
    OperationalStatusEnum, SecurityConditionEnum, VulnerabilityStatusEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.state_engine import state_engine

def run_state_engine_suite():
    print("=" * 80)
    print("       WEEK 7 - DAY 43: DIGITAL TWIN STATE ENGINE VALIDATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    state_engine.clear()

    # 1. Setup Base Device
    print("[1/5] Provisioning Base Device (web-01) in Registry...")
    dev = NetworkDeviceModel(
        id="web-01", hostname="WEB-SERVER-01", type=DeviceTypeEnum.SERVER,
        ipAddresses=["192.168.20.10"], networkZone=NetworkZoneEnum.DMZ, ports=[80, 443]
    )
    device_registry.createDevice(dev)
    print("  [PASS] Device 'web-01' provisioned in registry.")

    # 2. Initial State Initialization matching Day 43 prompt specification
    print("\n[2/5] Creating Initial State Vector for WEB-SERVER-01...")
    initial_state = ComprehensiveDeviceStateModel(
        deviceId="web-01",
        operationalState=OperationalStatusEnum.ACTIVE,
        performance=PerformanceStateModel(cpu=42.0, memory=67.0, networkUtilisation=35.0),
        network=NetworkTelemetryStateModel(activeConnections=24),
        ports=[
            PortStateEntry(port=80, protocol="TCP", state="OPEN", service="http"),
            PortStateEntry(port=443, protocol="TCP", state="OPEN", service="https")
        ],
        services=[
            ServiceRuntimeEntry(name="HTTP", status="RUNNING", port=80),
            ServiceRuntimeEntry(name="HTTPS", status="RUNNING", port=443)
        ],
        security=SecurityStateBlockModel(
            status=SecurityConditionEnum.NORMAL,
            vulnerabilityStatus=VulnerabilityStatusEnum.OPEN,
            activeVulnerabilitiesCount=2,
            compositeRiskScore=18.5
        )
    )
    saved_state = state_engine.updateDeviceState(initial_state, reason="Initial boot telemetry")

    assert saved_state.deviceId == "web-01"
    assert saved_state.performance.cpu == 42.0
    assert saved_state.performance.memory == 67.0
    assert saved_state.network.activeConnections == 24
    assert len(saved_state.ports) == 2
    assert len(saved_state.services) == 2
    assert saved_state.security.activeVulnerabilitiesCount == 2
    print("  [PASS] Initial state vector matches specification.")

    # 3. Step-by-Step Performance Evolution & History Logging (32% -> 45% -> 71% -> 91%)
    print("\n[3/5] Testing Performance Telemetry Updates & History Ledger...")
    cpu_progression = [32.0, 45.0, 71.0, 91.0]
    for target_cpu in cpu_progression:
        state_engine.updatePerformanceState(
            "web-01",
            PerformanceStateModel(cpu=target_cpu, memory=67.0, networkUtilisation=35.0),
            reason=f"Telemetry tick: CPU at {target_cpu}%"
        )
        current = state_engine.getDeviceState("web-01")
        assert current.performance.cpu == target_cpu

    # Audit history ledger
    history = state_engine.getStateHistory(device_id="web-01", component="performance")
    print(f"  Recorded Performance History Entries: {len(history)}")
    for h in history:
        print(f"    - [{h.timestamp}] Prev CPU: {h.previousValue.get('cpu')}% -> New CPU: {h.newValue.get('cpu')}% | Reason: {h.reason}")

    assert len(history) == 4
    assert history[0].newValue.get("cpu") == 32.0
    assert history[-1].newValue.get("cpu") == 91.0
    print("  [PASS] Immutable transition ledger verified.")

    # 4. State Invariant Boundary Violations (Negative CPU, CPU > 100, Memory > 100, Network > 100)
    print("\n[4/5] Testing Invariant Boundary Violations...")

    # Negative CPU
    try:
        PerformanceStateModel(cpu=-5.0, memory=50.0, networkUtilisation=10.0)
        assert False, "Failed to reject negative CPU!"
    except ValidationError as e:
        print("  [PASS] Rejected negative CPU.")

    # CPU > 100
    try:
        PerformanceStateModel(cpu=105.0, memory=50.0, networkUtilisation=10.0)
        assert False, "Failed to reject CPU > 100!"
    except ValidationError as e:
        print("  [PASS] Rejected CPU > 100%.")

    # Memory > 100
    try:
        PerformanceStateModel(cpu=50.0, memory=142.0, networkUtilisation=10.0)
        assert False, "Failed to reject Memory > 100!"
    except ValidationError as e:
        print("  [PASS] Rejected Memory > 100%.")

    # Network Saturation > 100
    try:
        PerformanceStateModel(cpu=50.0, memory=50.0, networkUtilisation=150.0)
        assert False, "Failed to reject Network > 100!"
    except ValidationError as e:
        print("  [PASS] Rejected Network Saturation > 100%.")

    # 5. Unknown Device Rejection
    print("\n[5/5] Testing Unknown Device Rejection...")
    try:
        state_engine.updateOperationalState("ghost-server", OperationalStatusEnum.OFFLINE)
        assert False, "Failed to reject unprovisioned device!"
    except DeviceNotFoundError:
        print("  [PASS] Safely rejected unknown device.")

    print("\n" + "=" * 80)
    print("       ALL DIGITAL TWIN STATE ENGINE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_state_engine_suite()