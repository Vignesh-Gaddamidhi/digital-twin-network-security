import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.repeated_connection import RepeatedConnectionProfile
from packages.shared_types.src.master_scenario import (
    MasterScenarioDefinition, MasterScenarioStageConfig, ScenarioStageTypeEnum
)
from services.digital_twin.simulation.generators.repeated_connection_engine import repeated_connection_engine
from services.digital_twin.simulation.scenarios.scenario_runner import scenario_runner
from services.digital_twin.core.devices.network_device_registry import device_registry

def run_phase7_master_suite():
    print("=" * 80)
    print("      DAYS 63 & 64: PHASE 7 GRAND INTEGRATION & SCENARIO PLATFORM AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    repeated_connection_engine.clear()
    scenario_runner.reset()

    # 1. Day 63: Repeated Connection Attempts Test
    print("[1/4] Testing Day 63 Repeated Connection Attempts (100 attempts in 10s: 3 succ, 97 fail)...")
    rep_prof = RepeatedConnectionProfile(
        sourceDevice="client-01",
        destinationDevice="server-01",
        destinationPort=22,
        attemptCount=100,
        windowSeconds=10,
        expectedSuccessRate=0.03
    )

    rep_event, rep_packets = repeated_connection_engine.runScenario(rep_prof, simulation_id="sim-day63")

    print(f"    Total Connection Attempts : {rep_event.attemptCount}")
    print(f"    Successful Connections    : {rep_event.successfulCount}")
    print(f"    Failed Connections        : {rep_event.failedCount}")
    print(f"    Total Layer 4 Packets     : {len(rep_packets)}")

    assert rep_event.anomalyType == "REPEATED_CONNECTION"
    assert rep_event.attemptCount == 100
    assert rep_event.successfulCount == 3
    assert rep_event.failedCount == 97
    assert len(rep_packets) == 200 # SYN + (ACK/RST)
    print("    [PASS] Day 63 repeated connection attempt pattern verified.")

    # 2. Day 64: Build Canonical 11-Stage Master Scenario
    print("\n[2/4] Defining Complete 11-Stage Phase 7 Scenario (Normal -> Anomalies -> Recoveries)...")
    master_scenario = MasterScenarioDefinition(
        scenarioId="master-phase7-canonical-001",
        name="Phase 7 Grand Integration",
        seed=12345,
        stages=[
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.NORMAL_BASELINE, durationSeconds=5),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.TRAFFIC_SPIKE, durationSeconds=5, intensity=2.0),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=5),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.CONNECTION_ANOMALY, durationSeconds=5, intensity=1.0),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=5),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.PORT_ANOMALY, durationSeconds=5),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=5),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.PROTOCOL_ANOMALY, durationSeconds=6),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=5),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.REPEATED_CONNECTION, durationSeconds=5, intensity=1.0),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=5),
        ]
    )
    print(f"    Total Stages: {len(master_scenario.stages)}")
    assert len(master_scenario.stages) == 11

    # 3. Execute ScenarioRunner
    print("\n[3/4] Running Master Scenario via ScenarioRunner...")
    scenario_runner.loadScenario(master_scenario)
    status = scenario_runner.run()

    print(f"    Final Run State           : {status.state}")
    print(f"    Total Virtual Time        : {status.virtualTimeSeconds}s")
    print(f"    Total Packets Simulated   : {status.totalPacketsEmitted}")
    print(f"    Total Events Logged       : {status.totalEventsLogged}")
    print(f"    Anomalies Triggered Count : {status.anomaliesTriggeredCount}")

    assert status.state == "COMPLETED"
    assert status.currentStageIndex == 11
    assert status.virtualTimeSeconds == 56.0
    assert status.anomaliesTriggeredCount == 5 # 5 distinct anomalies triggered
    assert status.totalPacketsEmitted > 500
    print("    [PASS] Complete 11-stage master scenario executed and verified.")

    # 4. Deterministic Replay & Export Verification
    print("\n[4/4] Verifying Deterministic Replay and JSON Export...")
    exported_file = scenario_runner.exportResults()
    assert exported_file.exists()
    print(f"    [PASS] Exported run results: {exported_file.name}")

    replay_status = scenario_runner.replay()
    assert replay_status.state == "COMPLETED"
    assert replay_status.totalPacketsEmitted == status.totalPacketsEmitted
    assert replay_status.anomaliesTriggeredCount == status.anomaliesTriggeredCount
    print("    [PASS] Replay produced identical packet counts and anomaly triggers.")

    print("\n" + "=" * 80)
    print("   ALL DAYS 63 & 64 PHASE 7 MASTER INTEGRATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_phase7_master_suite()