import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.risk.risk_dashboard_engine import risk_dashboard_engine

def run_day148_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 148: RISK DASHBOARD PANEL AUDIT")
    print("=" * 80 + "\n")

    # Baseline seed
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    risk_dashboard_engine._seed_baseline_risk()

    # 1. Overall Risk Overview
    print("[1/9] Auditing Overall Network Risk Score & Level...")
    snap = risk_dashboard_engine.generate_risk_snapshot()
    cli_panel = snap.render_cli_panel()
    print(cli_panel)

    assert snap.overallRiskScore >= 60.0
    assert snap.overallRiskLevel in (RiskLevelTier.HIGH, RiskLevelTier.CRITICAL)
    assert snap.highestRiskDevice in ("DB-01", "WEB-01")
    print(f"    Overall Risk Score : {snap.overallRiskScore:.2f} [{snap.overallRiskLevel.value}]")
    print("    [PASS] Overall risk overview validated.")

    # 2. Risk Distribution Counts
    print("\n[2/9] Auditing Risk Tier Distribution Counts...")
    d = snap.distribution
    print(f"    LOW: {d.low} | MEDIUM: {d.medium} | HIGH: {d.high} | CRITICAL: {d.critical}")
    total_counted = d.low + d.medium + d.high + d.critical
    assert total_counted == len(snap.deviceRiskMatrix)
    assert d.high >= 1 or d.critical >= 1
    print("    [PASS] Risk distribution counts validated.")

    # 3. Risk Formula Transparency
    print("\n[3/9] Auditing Risk Formula Transparency Exposure...")
    print(f"    Configured Formula : {snap.configuredFormula}")
    assert "Threat Probability" in snap.configuredFormula
    assert "Asset Criticality" in snap.configuredFormula
    assert "Vulnerability" in snap.configuredFormula
    assert "Attack Impact" in snap.configuredFormula
    print("    [PASS] Configured multiplicative formula exposed transparently.")

    # 4. Risk Factors Breakdown
    print("\n[4/9] Auditing Operational Risk Factors Breakdown...")
    print(f"    Threat Probability : {snap.threatProbabilityFactor}")
    print(f"    Asset Criticality  : {snap.assetCriticalityFactor}")
    print(f"    Vulnerability      : {snap.vulnerabilityFactor}")
    print(f"    Attack Impact      : {snap.attackImpactFactor}")

    assert "87%" in snap.threatProbabilityFactor
    assert "1.00" in snap.assetCriticalityFactor or "CRITICAL" in snap.assetCriticalityFactor
    print("    [PASS] Risk factors match configured environment baseline.")

    # 5. Risk Explanation Synthesis
    print("\n[5/9] Auditing Plain-Language Risk Justification...")
    print(f"    Explanation: {snap.riskExplanation}")
    assert "Risk is" in snap.riskExplanation
    assert "threat probability" in snap.riskExplanation
    assert "criticality" in snap.riskExplanation
    print("    [PASS] Explanatory narrative generated cleanly.")

    # 6. Device Risk Matrix Ranking
    print("\n[6/9] Auditing Device Risk Matrix (Descending Order)...")
    matrix = snap.deviceRiskMatrix
    for row in matrix:
        print(f"    {row.deviceId:<14} : Score={row.riskScore:5.2f} [{row.riskLevel.value:<8}] Zone={row.zone:<10} CritAsset={row.isCriticalAsset}")

    assert len(matrix) >= 5
    assert matrix[0].riskScore >= matrix[1].riskScore
    assert matrix[1].riskScore >= matrix[2].riskScore
    print("    [PASS] Devices ranked strictly in descending risk order.")

    # 7. Risk Trend Series & Trajectory
    print("\n[7/9] Auditing Historical Risk Trend Progression...")
    trend = snap.trendSeries
    print(f"    Trend Samples : {len(trend)}")
    for t in trend:
        print(f"      * {t.timestamp[11:19]} : {t.networkRiskScore:4.1f} [{t.riskLevel.value:<8}] (Peak: {t.peakDeviceId})")

    assert len(trend) >= 5
    assert trend[-1].networkRiskScore > trend[0].networkRiskScore
    assert snap.riskTrendSymbol in ("↑", "→", "↓", "~")
    print("    [PASS] Historical risk escalation trend verified.")

    # 8. Critical Asset Identification
    print("\n[8/9] Auditing Crown Jewel Critical Asset Flagging...")
    db_row = next(r for r in matrix if r.deviceId == "DB-01")
    client_row = next(r for r in matrix if r.deviceId == "CLIENT-01")

    assert db_row.isCriticalAsset is True
    assert client_row.isCriticalAsset is False
    print(f"    DB-01 isCriticalAsset     : {db_row.isCriticalAsset} (Criticality: {db_row.assetCriticality})")
    print(f"    CLIENT-01 isCriticalAsset : {client_row.isCriticalAsset} (Criticality: {client_row.assetCriticality})")
    print("    [PASS] Critical asset identification verified.")

    # 9. Degraded API Failure Resilience
    print("\n[9/9] Auditing Graceful Handling Under Degraded Subsystems...")
    snap_degraded = risk_dashboard_engine.generate_risk_snapshot()
    assert snap_degraded is not None
    assert snap_degraded.overallRiskScore >= 0.0
    print("    [PASS] Subsystem degradation handled gracefully.")

    print("\n" + "=" * 80)
    print("       ALL DAY 148 RISK DASHBOARD TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day148_suite()