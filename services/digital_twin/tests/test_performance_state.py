import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.performance import (
    PerformanceLevelEnum, PerformanceMetricSnapshot, PerformanceTelemetryPayload
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.performance_state_engine import performance_state_engine

def run_performance_state_suite():
    print("=" * 80)
    print("       WEEK 7 - DAY 45: CPU & MEMORY PERFORMANCE STATE ENGINE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    performance_state_engine.clear()

    # 1. Provision Target Device (WEB-01)
    print("[1/5] Provisioning Base Device (WEB-01) in Registry...")
    web = NetworkDeviceModel(
        id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ
    )
    device_registry.createDevice(web)
    assert performance_state_engine.getPerformanceState("web-01").performanceState == PerformanceLevelEnum.NORMAL
    print("    [PASS] Device 'web-01' provisioned with baseline metrics.")

    # 2. Test Threshold Grading
    print("\n[2/5] Testing Threshold Level Categorization...")
    assert performance_state_engine.calculateLevel(0.0) == PerformanceLevelEnum.NORMAL
    assert performance_state_engine.calculateLevel(59.9) == PerformanceLevelEnum.NORMAL
    assert performance_state_engine.calculateLevel(60.0) == PerformanceLevelEnum.ELEVATED
    assert performance_state_engine.calculateLevel(79.9) == PerformanceLevelEnum.ELEVATED
    assert performance_state_engine.calculateLevel(80.0) == PerformanceLevelEnum.HIGH
    assert performance_state_engine.calculateLevel(94.9) == PerformanceLevelEnum.HIGH
    assert performance_state_engine.calculateLevel(95.0) == PerformanceLevelEnum.CRITICAL
    assert performance_state_engine.calculateLevel(100.0) == PerformanceLevelEnum.CRITICAL
    print("    [PASS] All threshold ranges (0-60%, 60-80%, 80-95%, 95-100%) mapped accurately.")

    # 3. Test Combined Performance State Scenarios
    print("\n[3/5] Testing Combined Performance State Scenarios...")
    
    # Scenario A: CPU 43% (NORMAL), Memory 71% (ELEVATED) -> Combined: ELEVATED
    snap_a = performance_state_engine.recordTelemetry("web-01", cpu=43.0, memory=71.0)
    assert snap_a.cpuLevel == PerformanceLevelEnum.NORMAL
    assert snap_a.memoryLevel == PerformanceLevelEnum.ELEVATED
    assert snap_a.performanceState == PerformanceLevelEnum.ELEVATED
    print(f"    Scenario A: CPU=43% ({snap_a.cpuLevel.value}), Memory=71% ({snap_a.memoryLevel.value}) -> Combined: {snap_a.performanceState.value}")

    # Scenario B: CPU 92% (HIGH), Memory 89% (HIGH) -> Combined: HIGH
    snap_b = performance_state_engine.recordTelemetry("web-01", cpu=92.0, memory=89.0)
    assert snap_b.cpuLevel == PerformanceLevelEnum.HIGH
    assert snap_b.memoryLevel == PerformanceLevelEnum.HIGH
    assert snap_b.performanceState == PerformanceLevelEnum.HIGH
    print(f"    Scenario B: CPU=92% ({snap_b.cpuLevel.value}), Memory=89% ({snap_b.memoryLevel.value}) -> Combined: {snap_b.performanceState.value}")

    # Scenario C: CPU 99% (CRITICAL), Memory 97% (CRITICAL) -> Combined: CRITICAL
    snap_c = performance_state_engine.recordTelemetry("web-01", cpu=99.0, memory=97.0)
    assert snap_c.cpuLevel == PerformanceLevelEnum.CRITICAL
    assert snap_c.memoryLevel == PerformanceLevelEnum.CRITICAL
    assert snap_c.performanceState == PerformanceLevelEnum.CRITICAL
    print(f"    Scenario C: CPU=99% ({snap_c.cpuLevel.value}), Memory=97% ({snap_c.memoryLevel.value}) -> Combined: {snap_c.performanceState.value}")

    # 4. Invariant Tests: 0, 50, 100, -1, 101 for both CPU and Memory
    print("\n[4/5] Testing Boundary Conditions (0, 50, 100, -1, 101)...")
    
    # Valid CPU boundaries
    for valid_val in [0.0, 50.0, 100.0]:
        res = performance_state_engine.updateCpu("web-01", valid_val)
        assert res.cpu == valid_val
        print(f"    [PASS] CPU = {valid_val} accepted.")

    # Invalid CPU boundaries
    for invalid_val in [-1.0, 101.0]:
        try:
            performance_state_engine.updateCpu("web-01", invalid_val)
            assert False, f"Failed to reject invalid CPU value {invalid_val}!"
        except ValueError:
            print(f"    [PASS] CPU = {invalid_val} correctly rejected.")

    # Valid Memory boundaries
    for valid_val in [0.0, 50.0, 100.0]:
        res = performance_state_engine.updateMemory("web-01", valid_val)
        assert res.memory == valid_val
        print(f"    [PASS] Memory = {valid_val} accepted.")

    # Invalid Memory boundaries
    for invalid_val in [-1.0, 101.0]:
        try:
            performance_state_engine.updateMemory("web-01", invalid_val)
            assert False, f"Failed to reject invalid Memory value {invalid_val}!"
        except ValueError:
            print(f"    [PASS] Memory = {invalid_val} correctly rejected.")

    # 5. History Audit & Unknown Device Handling
    print("\n[5/5] Auditing History Ledger and Unknown Device Protection...")
    history = performance_state_engine.getHistory("web-01")
    print(f"    Recorded Telemetry History Entries: {len(history)}")
    for h in history[-3:]:
        print(f"      [{h.timestamp}] CPU: {h.cpu}% ({h.cpuLevel.value}), Mem: {h.memory}% ({h.memoryLevel.value}) | State: {h.performanceState.value} | Src: {h.source}")

    assert len(history) >= 9

    # Unknown device protection
    try:
        performance_state_engine.recordTelemetry("ghost-server", cpu=50.0, memory=50.0)
        assert False, "Failed to reject unknown device!"
    except DeviceNotFoundError:
        print("    [PASS] Unknown device correctly rejected.")

    print("\n" + "=" * 80)
    print("       ALL PERFORMANCE STATE ENGINE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_performance_state_suite()