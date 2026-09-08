import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.traffic_spike import (
    TrafficSpikeProfile, SpikePhaseEnum, TrafficSpikeRunResult
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.simulation.generators.traffic_spike_engine import traffic_spike_engine

def run_traffic_spike_suite():
    print("=" * 80)
    print("       WEEK 9 - DAY 59: TRAFFIC SPIKE & DYNAMIC METRIC SURGE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    network_state_engine.clear()
    performance_state_engine.clear()

    # 1. Configure Scenario: 100 events/min -> 800 events/min
    print("[1/4] Configuring Traffic Spike Profile (100 -> 800 events/min)...")
    profile = TrafficSpikeProfile(
        name="Day59-Web-Spike-Scenario",
        affectedDevice="client-01",
        targetDevice="web-01",
        targetPort=443,
        baselineRate=100.0,
        spikeRate=800.0,
        baselineDuration=3,
        rampUpTime=2,
        spikeDuration=6,
        rampDownTime=2,
        recoveryDuration=3
    )

    expected_duration = 3 + 2 + 6 + 2 + 3 # 16 seconds total
    print(f"    Total Expected Duration: {expected_duration}s")
    assert profile.baselineRate == 100.0
    assert profile.spikeRate == 800.0
    print("    [PASS] Profile initialized.")

    # 2. Execute Spike Scenario
    print("\n[2/4] Executing Volumetric Curve (Normal -> RampUp -> Peak -> RampDown -> Recovery)...")
    result = traffic_spike_engine.runSpikeScenario(profile, sync_to_twin=True)

    print(f"    Total Events Emitted     : {result.totalEventsEmitted}")
    print(f"    Total Bytes Transferred  : {result.totalBytesTransferred} bytes")
    print(f"    Max Network Utilisation  : {result.maxNetworkUtilisation}%")
    print(f"    Max Active Connections   : {result.maxActiveConnections}")
    print(f"    Max CPU Load Observed    : {result.maxCpuLoad}%")

    assert result.totalDurationSeconds == expected_duration
    assert len(result.telemetryTimeline) == expected_duration
    assert result.peakRatePerMinObserved == 800.0
    print("    [PASS] Execution progressed through all 16 seconds.")

    # 3. Verify Phase Transitions & Digital Twin Metric Feedback
    print("\n[3/4] Auditing Timeline Metric Curves Across Phases...")
    base_ticks = [t for t in result.telemetryTimeline if t.phase == SpikePhaseEnum.BASELINE]
    peak_ticks = [t for t in result.telemetryTimeline if t.phase == SpikePhaseEnum.PEAK]
    rec_ticks = [t for t in result.telemetryTimeline if t.phase == SpikePhaseEnum.RECOVERY]

    print(f"    Baseline Phase  : Rate={base_ticks[0].currentRatePerMin}/min | Util={base_ticks[0].simulatedNetworkUtilisation}% | Conns={base_ticks[0].simulatedActiveConnections} | CPU={base_ticks[0].simulatedCpuLoad}%")
    print(f"    Peak Spike Phase: Rate={peak_ticks[0].currentRatePerMin}/min | Util={peak_ticks[0].simulatedNetworkUtilisation}% | Conns={peak_ticks[0].simulatedActiveConnections} | CPU={peak_ticks[0].simulatedCpuLoad}%")
    print(f"    Recovery Phase  : Rate={rec_ticks[-1].currentRatePerMin}/min | Util={rec_ticks[-1].simulatedNetworkUtilisation}% | Conns={rec_ticks[-1].simulatedActiveConnections} | CPU={rec_ticks[-1].simulatedCpuLoad}%")

    # Verify Baseline values
    assert base_ticks[0].currentRatePerMin == 100.0
    assert base_ticks[0].simulatedNetworkUtilisation == 20.0
    assert base_ticks[0].simulatedActiveConnections == 5

    # Verify Peak values jump significantly
    assert peak_ticks[0].currentRatePerMin == 800.0
    assert peak_ticks[0].simulatedNetworkUtilisation >= 90.0
    assert peak_ticks[0].simulatedActiveConnections >= 35
    assert peak_ticks[0].simulatedCpuLoad >= 80.0

    # Verify Recovery drops back to baseline
    assert rec_ticks[-1].currentRatePerMin == 100.0
    assert rec_ticks[-1].simulatedNetworkUtilisation == 20.0
    assert rec_ticks[-1].simulatedActiveConnections == 5
    assert rec_ticks[-1].simulatedCpuLoad == 25.0
    print("    [PASS] Network utilisation, connection counts, and CPU accurately traced the volumetric curve.")

    # 4. Check Digital Twin Current State
    print("\n[4/4] Verifying Digital Twin State Reflection...")
    curr_net = network_state_engine.getNetworkMetrics("web-01")
    curr_perf = performance_state_engine.getPerformanceState("web-01")

    print(f"    WEB-01 Twin Current State -> Inbound Bytes: {curr_net.bytesReceived}, Packets: {curr_net.packetsReceived}, CPU: {curr_perf.cpu}%")
    assert curr_net.bytesReceived == result.totalBytesTransferred
    assert curr_net.packetsReceived == result.totalEventsEmitted
    print("    [PASS] State Engine synchronized with all injected wire telemetry.")

    print("\n" + "=" * 80)
    print("       ALL DAY 59 TRAFFIC SPIKE SIMULATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_traffic_spike_suite()