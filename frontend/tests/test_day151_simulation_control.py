import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from frontend.dashboard.dashboard_engine import dashboard_engine
from frontend.simulations.simulation_models import (
    SimulationExecutionState, SimulationStageEnum, ScenarioIdentifierEnum
)
from frontend.simulations.simulation_control_engine import simulation_control_engine

def run_day151_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 151: SIMULATION CONTROL CENTER AUDIT")
    print("=" * 80 + "\n")

    # 1. Scenario Selection & Configuration
    print("[1/8] Auditing Scenario Selection & Reproducibility Meta...")
    st_init = simulation_control_engine.select_scenario(
        scenario=ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE,
        duration_seconds=120,
        seed=42,
        speed=1.0
    )
    cli_panel = st_init.render_cli_panel()
    print(cli_panel)

    assert st_init.executionState == SimulationExecutionState.IDLE
    assert st_init.activeScenario == ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE
    assert st_init.reproducibility.seed == 42
    assert "LATERAL_MOVEMENT_LIKE" in st_init.reproducibility.scenarioId
    print("    [PASS] Scenario configuration and reproducibility verified.")

    # 2. Lifecycle Actions: Start, Pause, Resume, Stop
    print("\n[2/8] Auditing Lifecycle Actions (START -> PAUSE -> RESUME -> STOP)...")
    st_start = simulation_control_engine.start()
    assert st_start.executionState == SimulationExecutionState.RUNNING
    print(f"    Action START  : State = {st_start.executionState.value}")

    st_pause = simulation_control_engine.pause()
    assert st_pause.executionState == SimulationExecutionState.PAUSED
    print(f"    Action PAUSE  : State = {st_pause.executionState.value}")

    st_resume = simulation_control_engine.resume()
    assert st_resume.executionState == SimulationExecutionState.RUNNING
    print(f"    Action RESUME : State = {st_resume.executionState.value}")

    st_stop = simulation_control_engine.stop()
    assert st_stop.executionState == SimulationExecutionState.STOPPED
    print(f"    Action STOP   : State = {st_stop.executionState.value}")
    print("    [PASS] Execution lifecycle states validated.")

    # 3. Reset Action
    print("\n[3/8] Auditing RESET Action...")
    st_reset = simulation_control_engine.reset()
    assert st_reset.executionState == SimulationExecutionState.IDLE
    assert st_reset.elapsedSeconds == 0
    assert st_reset.currentStage == SimulationStageEnum.NORMAL
    print(f"    Action RESET  : State = {st_reset.executionState.value}, Elapsed = {st_reset.elapsedSeconds}s")
    print("    [PASS] Reset returns state to clean baseline.")

    # 4. Multi-Stage Timeline Progression (NORMAL -> EARLY -> ESCALATION -> IMPACT -> RECOVERY)
    print("\n[4/8] Auditing Multi-Stage Timeline Progression via Tick Advances...")
    simulation_control_engine.start()

    # Advance to 10s (8.3% -> NORMAL)
    s_norm = simulation_control_engine.advance_ticks(10)
    print(f"    T=10s  ({s_norm.progressPercent:4.1f}%): Stage = {s_norm.currentStage.value:<16} Pkts/s = {s_norm.currentPacketsPerSec}")
    assert s_norm.currentStage == SimulationStageEnum.NORMAL

    # Advance to 35s (29.2% -> EARLY_INDICATORS)
    s_early = simulation_control_engine.advance_ticks(25)
    print(f"    T=35s  ({s_early.progressPercent:4.1f}%): Stage = {s_early.currentStage.value:<16} Pkts/s = {s_early.currentPacketsPerSec}")
    assert s_early.currentStage == SimulationStageEnum.EARLY_INDICATORS

    # Advance to 65s (54.2% -> ESCALATION)
    s_escala = simulation_control_engine.advance_ticks(30)
    print(f"    T=65s  ({s_escala.progressPercent:4.1f}%): Stage = {s_escala.currentStage.value:<16} Pkts/s = {s_escala.currentPacketsPerSec} (Risk: {s_escala.networkRiskScore})")
    assert s_escala.currentStage == SimulationStageEnum.ESCALATION

    # Advance to 95s (79.2% -> IMPACT)
    s_impact = simulation_control_engine.advance_ticks(30)
    print(f"    T=95s  ({s_impact.progressPercent:4.1f}%): Stage = {s_impact.currentStage.value:<16} Pkts/s = {s_impact.currentPacketsPerSec} (Risk: {s_impact.networkRiskScore})")
    assert s_impact.currentStage == SimulationStageEnum.IMPACT

    # Advance to 115s (95.8% -> RECOVERY)
    s_rec = simulation_control_engine.advance_ticks(20)
    print(f"    T=115s ({s_rec.progressPercent:4.1f}%): Stage = {s_rec.currentStage.value:<16} Pkts/s = {s_rec.currentPacketsPerSec}")
    assert s_rec.currentStage == SimulationStageEnum.RECOVERY
    print("    [PASS] All 5 simulation stages traversed sequentially.")

    # 5. Cascading Dashboard Updates Verification
    print("\n[5/8] Auditing Cascading Impact to Dashboard KPI State...")
    dash_kpi = dashboard_engine.current_state.kpi
    print(f"    Dashboard Live KPI : Packets/s={dash_kpi.packetsPerSecond}, Threats={dash_kpi.activeThreats}, Risk={dash_kpi.networkRiskScore}")
    assert dash_kpi.packetsPerSecond > 0.0
    print("    [PASS] Simulation state cascaded to dashboard KPI telemetry.")

    # 6. Completion State on Timeline Finish
    print("\n[6/8] Auditing Simulation Completion at 100% Duration...")
    s_done = simulation_control_engine.advance_ticks(10)
    print(f"    Final Time Display : {s_done.timeDisplay} (Progress: {s_done.progressPercent}%)")
    print(f"    Execution State    : {s_done.executionState.value}")
    assert s_done.executionState == SimulationExecutionState.COMPLETED
    assert s_done.progressPercent == 100.0
    print("    [PASS] Simulation completed successfully.")

    # 7. Speed Multiplier Scaling
    print("\n[7/8] Auditing Speed Multiplier Scaling (2.0x Speed)...")
    s_speed = simulation_control_engine.select_scenario(
        scenario=ScenarioIdentifierEnum.PORT_SCAN,
        duration_seconds=100,
        speed=2.0
    )
    simulation_control_engine.start()
    # Advancing 10 real seconds with 2.0x speed should advance 20 simulation seconds
    s_fast = simulation_control_engine.advance_ticks(10)
    print(f"    10s real tick @ 2.0x speed -> Elapsed: {s_fast.elapsedSeconds}s (Expected: 20s)")
    assert s_fast.elapsedSeconds == 20
    print("    [PASS] Speed multiplier scaling verified.")

    # 8. Reset to Clean State
    print("\n[8/8] Resetting Simulation Environment...")
    simulation_control_engine.reset()
    assert simulation_control_engine.live_state.executionState == SimulationExecutionState.IDLE
    print("    [PASS] Simulation state reset clean.")

    print("\n" + "=" * 80)
    print("       ALL DAY 151 SIMULATION CONTROL CENTER TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day151_suite()