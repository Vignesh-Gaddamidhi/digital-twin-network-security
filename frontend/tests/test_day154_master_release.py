import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.simulations.simulation_models import ScenarioIdentifierEnum
from frontend.dashboard.phase18_graduation_orchestrator import phase18_graduation_orchestrator

def run_day154_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 154: MASTER DASHBOARD INTEGRATION & RELEASE AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. Master Dashboard Screen Rendering
    print("[1/8] Auditing Master Dashboard Screen Assembly...")
    view = phase18_graduation_orchestrator.get_master_dashboard_view()
    cli_screen = view.render_master_cli_screen()
    print(cli_screen)

    assert view.systemStatus == "SYSTEM ACTIVE"
    assert view.kpi.devices.totalDevices >= 5
    assert view.topPrediction is not None
    print("    [PASS] Master dashboard screen assembled with all lower analytics panels.")

    # 2. E2E Scenario Execution: LATERAL_MOVEMENT_LIKE
    print("\n[2/8] Auditing E2E Scenario: LATERAL_MOVEMENT_LIKE...")
    res_lat = phase18_graduation_orchestrator.run_end_to_end_scenario(ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE)
    print(f"    Stage: {res_lat['simulationStage']} | Risk: {res_lat['riskScore']:.1f} [{res_lat['riskLevel']}] | Category: {res_lat['predictedCategory']}")
    assert res_lat["simulationStage"] == "ESCALATION"
    assert res_lat["riskScore"] > 50.0
    print("    [PASS] LATERAL_MOVEMENT_LIKE pipeline executed end-to-end.")

    # 3. Baseline Scenario Execution: NORMAL
    print("\n[3/8] Auditing Baseline Scenario: NORMAL...")
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    res_norm = phase18_graduation_orchestrator.run_end_to_end_scenario(ScenarioIdentifierEnum.NORMAL)
    print(f"    Stage: {res_norm['simulationStage']} | Threats: {res_norm['threatsCount']} | Risk Score: {res_norm['riskScore']:.1f}")
    assert res_norm["threatsCount"] <= 2
    assert res_norm["riskScore"] <= 70.0  # Baseline network risk with present CVE-2026-WEB-RCE
    print("    [PASS] Normal benign scenario executed with baseline conditions.")

    # 4. Volumetric Scenario Execution: TRAFFIC_SPIKE
    print("\n[4/8] Auditing Volumetric Scenario: TRAFFIC_SPIKE...")
    res_spike = phase18_graduation_orchestrator.run_end_to_end_scenario(ScenarioIdentifierEnum.TRAFFIC_SPIKE)
    print(f"    Stage: {res_spike['simulationStage']} | Risk: {res_spike['riskScore']:.1f}")
    assert res_spike["riskScore"] > 40.0
    print("    [PASS] TRAFFIC_SPIKE scenario executed.")

    # 5. Port Anomaly Scenario Execution: PORT_ANOMALY
    print("\n[5/8] Auditing Reconnaissance Scenario: PORT_ANOMALY...")
    res_port = phase18_graduation_orchestrator.run_end_to_end_scenario(ScenarioIdentifierEnum.PORT_ANOMALY)
    print(f"    Stage: {res_port['simulationStage']} | Threats: {res_port['threatsCount']}")
    assert res_port["threatsCount"] >= 1
    print("    [PASS] PORT_ANOMALY scenario executed.")

    # 6. Dynamic Vulnerability Remediation Demonstration
    print("\n[6/8] Auditing Virtual Patch Remediation (WEB-01 CVE-2026-WEB-RCE)...")
    rem = phase18_graduation_orchestrator.execute_remediation_audit()
    print(f"    Pre-Patch Risk  : {rem['riskScoreBefore']:.2f}")
    print(f"    Post-Patch Risk : {rem['riskScoreAfter']:.2f}")
    assert rem["riskReduced"] is True
    print("    [PASS] Virtual patch remediation dynamically decreased network risk.")

    # 7. Dynamic Host Isolation Demonstration
    print("\n[7/8] Auditing Host Quarantine Containment (CLIENT-01)...")
    iso = phase18_graduation_orchestrator.execute_isolation_audit()
    print(f"    Quarantined Host    : {iso['isolationTarget']}")
    print(f"    Attack Path Severed : {iso['attackPathSevered']}")
    assert iso["attackPathSevered"] is True
    print("    [PASS] Host isolation severed viable traversal reachability.")

    # 8. Master Dashboard Rendering Performance Profiling
    print("\n[8/8] Auditing Master Dashboard Load & Rendering Latencies...")
    perf = phase18_graduation_orchestrator.profile_dashboard_performance()
    for comp, ms in perf.items():
        print(f"    {comp:<28} : {ms:6.3f} ms")
    assert perf["totalMasterDashboardLoadMs"] < 25.0
    print(f"    [PASS] Total Master Dashboard Render: {perf['totalMasterDashboardLoadMs']} ms (< 25ms SLA).")

    print("\n" + "=" * 80)
    print("       ALL DAY 154 MASTER INTEGRATION & RELEASE TESTS PASSED")
    print("       PHASE 18 GRADUATED SUCCESSFULLY — READY FOR MILESTONE TAGGING")
    print("================================================================================")

if __name__ == "__main__":
    run_day154_suite()