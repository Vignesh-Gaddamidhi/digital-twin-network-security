import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.protocol_anomaly import (
    ProtocolWindowPhaseEnum, ProtocolAnomalyRunResult
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.simulation.generators.protocol_anomaly_engine import protocol_anomaly_engine

def run_protocol_anomaly_suite():
    print("=" * 80)
    print("       WEEK 9 - DAY 62: UNUSUAL PROTOCOL BEHAVIOUR SIMULATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    protocol_anomaly_engine.clear()

    # 1. Execute 3-Stage Protocol Scenario (Normal -> Abnormal -> Recovery)
    print("[1/4] Executing 3-Stage Protocol Shift Scenario (Normal -> Abnormal -> Recovery)...")
    result = protocol_anomaly_engine.runThreeStageScenario(
        source_dev="client-01",
        dest_dev="web-01",
        window_duration=10,
        packets_per_second=10,
        simulation_id="sim-day62"
    )

    print(f"    Total Duration : {result.totalDurationSeconds}s across 3 windows.")
    print(f"    Total Packets  : {result.totalEvents}")
    assert result.totalDurationSeconds == 30
    assert result.totalEvents == 300
    print("    [PASS] Completed all 3 operational windows.")

    # 2. Verify Window 1: Normal Profile (HTTPS ~60%, ICMP ~5%)
    print("\n[2/4] Auditing Window 1: Normal Profile...")
    w1 = result.normalWindowStats
    print("    Window 1 Percentages:", w1.percentages)
    assert w1.windowPhase == ProtocolWindowPhaseEnum.NORMAL_PERIOD
    assert w1.percentages["HTTPS"] > 45.0  # Around 60%
    assert w1.percentages["ICMP"] < 15.0   # Around 5%
    print("    [PASS] Normal Profile verified: HTTPS is dominant.")

    # 3. Verify Window 2: Abnormal Profile (ICMP ~65%, HTTPS ~20%)
    print("\n[3/4] Auditing Window 2: Abnormal Skew Profile...")
    w2 = result.abnormalWindowStats
    print("    Window 2 Percentages:", w2.percentages)
    assert w2.windowPhase == ProtocolWindowPhaseEnum.ABNORMAL_PERIOD
    assert w2.percentages["ICMP"] > 50.0   # Jumps to ~65%
    assert w2.percentages["HTTPS"] < 35.0  # Drops to ~20%
    print("    [PASS] Abnormal Profile verified: ICMP severely skews the distribution.")

    # 4. Verify Window 3: Recovery Profile & Emitted Anomaly Event
    print("\n[4/4] Auditing Window 3 (Recovery) and Structured Anomaly Audit Events...")
    w3 = result.recoveryWindowStats
    print("    Window 3 Percentages:", w3.percentages)
    assert w3.windowPhase == ProtocolWindowPhaseEnum.RECOVERY_PERIOD
    assert w3.percentages["HTTPS"] > 45.0
    assert w3.percentages["ICMP"] < 15.0
    print("    [PASS] Recovery Window verified: Protocol distribution restored to normal baseline.")

    # Check Anomaly Event Schema
    assert len(result.detectedAnomalies) >= 1
    anom = result.detectedAnomalies[0]
    print(f"    Anomaly Event Detected: Type='{anom.anomalyType}', Expected='{anom.expectedDominantProtocol}', Observed='{anom.observedDominantProtocol}', Deviation={anom.deviation}")

    assert anom.anomalyType == "PROTOCOL_ANOMALY"
    assert anom.expectedDominantProtocol == "HTTPS"
    assert anom.observedDominantProtocol == "ICMP"
    assert anom.deviation >= 0.50
    print("    [PASS] Neutral PROTOCOL_ANOMALY event emitted with exact deviation metrics.")

    print("\n" + "=" * 80)
    print("       ALL DAY 62 PROTOCOL ANOMALY TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_protocol_anomaly_suite()