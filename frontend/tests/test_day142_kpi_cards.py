import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
from frontend.dashboard.kpi_models import MasterKPISnapshot
from frontend.dashboard.kpi_summary_engine import kpi_summary_engine

def run_day142_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 142: KPI SUMMARY CARDS & AGGREGATION AUDIT")
    print("=" * 80 + "\n")

    # Seed baseline environment state
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    risk_state_engine.clear()
    risk_state_engine.record_risk_observation("DB-01", 78.40, "PRED-KPI-1")
    risk_state_engine.record_risk_observation("WEB-01", 60.80, "PRED-KPI-2")

    # 1. Device Count Aggregation
    print("[1/9] Auditing Device Count Breakdown (Total, Healthy, At Risk, Isolated)...")
    kpi = kpi_summary_engine.aggregate_live_kpis()
    d = kpi.devices
    print(f"    Total: {d.totalDevices} | Healthy: {d.healthyDevices} | At Risk: {d.atRiskDevices} | Isolated: {d.isolatedDevices}")
    assert d.totalDevices == 5
    assert d.totalDevices == (d.healthyDevices + d.atRiskDevices + d.isolatedDevices)
    print("    [PASS] Device count and category breakdown validated.")

    # 2. Threat Count Aggregation
    print("\n[2/9] Auditing Threat Count Breakdown by Severity...")
    t = kpi.threats
    print(f"    Total Threats: {t.totalThreats} | Critical: {t.criticalThreats} | High: {t.highThreats} | Medium: {t.mediumThreats}")
    assert t.totalThreats >= 1
    assert t.criticalThreats >= 1 or t.highThreats >= 1
    print("    [PASS] Threat counts categorized by severity.")

    # 3. Risk Score & Level Aggregation
    print("\n[3/9] Auditing Risk Aggregation & Trend Symbol Mapping...")
    r = kpi.risk
    print(f"    Risk Score: {r.overallRiskScore:.2f} | Level: {r.overallRiskLevel.value} | Trend Symbol: {r.riskTrendSymbol} ({r.riskTrendDirection})")
    print(f"    Peak Risk Device: {r.highestRiskDevice}")
    assert r.overallRiskScore > 50.0
    assert r.overallRiskLevel in (RiskLevelTier.HIGH, RiskLevelTier.CRITICAL)
    assert r.riskTrendSymbol in ("↑", "→", "↓", "~")
    print("    [PASS] Risk score, tier, and directional trend arrow validated.")

    # 4. Attack Count Decoupling (Detected vs Predicted vs Simulated)
    print("\n[4/9] Auditing Attack Concept Decoupling (Detected, Predicted, Simulated)...")
    a = kpi.attacks
    print(f"    Total Attacks : {a.totalAttacks}")
    print(f"    Detected      : {a.detectedAttacks} (Active telemetry violations)")
    print(f"    Predicted     : {a.predictedAttacks} (Time-series early warnings)")
    print(f"    Simulated     : {a.simulatedAttacks} (Controlled lab scenario events)")
    print(f"    Active Paths  : {a.activeAttackPaths}")
    assert a.detectedAttacks >= 1
    assert a.predictedAttacks >= 1
    assert a.simulatedAttacks >= 1
    print("    [PASS] Distinct attack categories maintained without conflation.")

    # 5. CLI Visual Formatted Card Rendering
    print("\n[5/9] Auditing Top-Level KPI CLI Formatted Display Card...")
    card_str = kpi.to_formatted_cli_card()
    print(card_str)
    assert "DIGITAL TWIN TOP-LEVEL KPI METRICS" in card_str
    assert "DEVICES" in card_str
    assert "THREATS" in card_str
    assert "RISK" in card_str
    assert "ATTACKS" in card_str
    print("    [PASS] CLI formatted KPI card validated.")

    # 6. Zero-State Fallback Handling
    print("\n[6/9] Auditing Zero-State Baseline...")
    zero = kpi_summary_engine.get_zero_state_kpis()
    assert zero.devices.totalDevices == 0
    assert zero.threats.totalThreats == 0
    assert zero.risk.overallRiskScore == 0.0
    assert zero.attacks.totalAttacks == 0
    print("    [PASS] Clean zero-state verified.")

    # 7. Stale Data Detection
    print("\n[7/9] Auditing Staleness Detection Threshold...")
    fresh_snapshot = kpi_summary_engine.aggregate_live_kpis()
    assert kpi_summary_engine.check_staleness(fresh_snapshot) is False

    # Simulate aged timestamp (> 60s ago)
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
    aged_snapshot = fresh_snapshot.model_copy(update={"lastRefreshedAt": old_time})
    assert kpi_summary_engine.check_staleness(aged_snapshot) is True
    print("    Fresh data: isStale=False | Aged data (>60s): isStale=True")
    print("    [PASS] Data staleness threshold verified.")

    # 8. Manual Refresh Behavior
    print("\n[8/9] Auditing Manual KPI Refresh Trigger...")
    refreshed = kpi_summary_engine.aggregate_live_kpis()
    assert refreshed.lastRefreshedAt is not None
    print(f"    Refreshed Timestamp: {refreshed.lastRefreshedAt}")
    print("    [PASS] Refresh produces valid timestamp.")

    # 9. Dynamic Posture Mutation Impact on KPI Cards
    print("\n[9/9] Auditing Posture Mutation Impact (Isolating Host CLIENT-01)...")
    twin_graph_synchronizer.isolate_device("CLIENT-01")
    mutated_kpi = kpi_summary_engine.aggregate_live_kpis()
    print(f"    Post-Isolation Devices: Isolated={mutated_kpi.devices.isolatedDevices}, Healthy={mutated_kpi.devices.healthyDevices}")
    assert mutated_kpi.devices.isolatedDevices == 1
    print("    [PASS] Host isolation dynamically reflected in KPI card.")

    # Reset environment
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    print("\n" + "=" * 80)
    print("       ALL DAY 142 KPI SUMMARY CARD TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day142_suite()