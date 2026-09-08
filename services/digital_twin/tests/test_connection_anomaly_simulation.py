import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.connection_anomaly import (
    ConnectionAnomalyProfile, ConnectionAnomalyPatternEnum, ConnectionAnomalyRunResult
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.simulation.generators.connection_anomaly_engine import connection_anomaly_engine

def run_connection_anomaly_suite():
    print("=" * 80)
    print("       WEEK 9 - DAY 60: CONNECTION ANOMALY SIMULATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    network_state_engine.clear()

    # 1. Configure Connection Anomaly Profile (Scaling to 100 conns)
    print("[1/4] Configuring Connection Anomaly Profile (5 -> 10 -> 20 -> 50 -> 100)...")
    profile = ConnectionAnomalyProfile(
        name="Web-Port-443-Connection-Bursts",
        affectedDevice="client-01",
        targetDevice="web-01",
        targetPort=443,
        protocol="TCP",
        normalConnectionRate=5,
        abnormalConnectionRate=100,
        lifecyclePattern=ConnectionAnomalyPatternEnum.HIGH_NEW_HIGH_FAILED
    )
    assert profile.normalConnectionRate == 5
    assert profile.abnormalConnectionRate == 100
    print("    [PASS] Profile initialized.")

    # 2. Execute Scenario
    print("\n[2/4] Executing Progressive Connection Bursts...")
    result = connection_anomaly_engine.runAnomalyScenario(profile, sync_to_twin=True)

    print(f"    Classification Tag       : {result.classification}")
    print(f"    Baseline Active Conns    : {result.baselineActiveConnections}")
    print(f"    Peak Active Conns        : {result.peakActiveConnections}")
    print(f"    Connection Tiers Visited : {result.connectionLevelsObserved}")
    print(f"    Total Wire Transactions  : {result.totalTransactions}")

    # Core Assertions
    assert result.classification == "UNUSUAL_CONNECTION_BEHAVIOUR"
    assert result.connectionLevelsObserved == [5, 10, 20, 50, 100]
    assert result.peakActiveConnections == 100
    print("    [PASS] Escalation ladder accurately walked tiers: [5, 10, 20, 50, 100].")

    # 3. Verify Lifecycle Breakdown Skew (Many NEW, Few ESTABLISHED, Many FAILED)
    print("\n[3/4] Auditing Session Lifecycle State Skew...")
    summary = result.lifecycleSummary
    print(f"    NEW Count         : {summary.newCount}")
    print(f"    ESTABLISHED Count : {summary.establishedCount}")
    print(f"    CLOSED Count      : {summary.closedCount}")
    print(f"    FAILED Count      : {summary.failedCount}")

    assert summary.newCount == (5 + 10 + 20 + 50 + 100) # 185 total attempts
    assert summary.failedCount > summary.establishedCount # High failure skew
    assert summary.failedCount > 100
    print("    [PASS] Lifecycle skew verified: High NEW, Low ESTABLISHED, High FAILED.")

    # 4. Verify Digital Twin Synchronization
    print("\n[4/4] Verifying Digital Twin State Reflection...")
    dev_conns = network_state_engine.getDeviceConnections("web-01")
    stats = network_state_engine.getConnectionStats("web-01")

    print(f"    WEB-01 Twin Stats -> Active: {stats.active}, Closed: {stats.closed}, Failed: {stats.failed}, Total: {stats.total}")
    assert stats.active >= 5
    assert stats.failed > 0
    print("    [PASS] Digital Twin accurately tracks anomalous active and failing sessions.")

    print("\n" + "=" * 80)
    print("       ALL DAY 60 CONNECTION ANOMALY TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_connection_anomaly_suite()