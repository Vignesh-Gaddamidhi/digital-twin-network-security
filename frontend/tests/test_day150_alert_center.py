import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.threats.threat_models import DetectionSourceEnum
from frontend.alerts.alert_center_models import (
    AlertStatusEnum, SecurityAlertItem, AlertFilterCriteria
)
from frontend.alerts.alert_center_engine import alert_center_engine

def run_day150_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 150: ALERT CENTER & SECURITY OPERATIONS AUDIT")
    print("=" * 80 + "\n")

    alert_center_engine._seed_default_alerts()

    # 1. Alert Creation & Table Rendering
    print("[1/10] Auditing Alert Table Generation & Field Population...")
    alerts = alert_center_engine.alerts
    cli_table = alert_center_engine.render_cli_alert_table(alerts)
    print(cli_table)

    assert len(alerts) >= 4
    a0 = alerts[0]
    print(f"    Alert ID    : {a0.alertId}")
    print(f"    Severity    : {a0.severity.value} (Risk: {a0.riskScore})")
    print(f"    Flow        : {a0.sourceDevice} -> {a0.destinationDevice}")
    print(f"    Event Type  : {a0.eventType} [{a0.detectionSource.value}]")
    print(f"    Status      : {a0.status.value}")

    assert a0.alertId == "ALT-004"
    assert a0.severity == RiskLevelTier.CRITICAL
    print("    [PASS] Alert table schema and columns verified.")

    # 2. Lifecycle Status Transitions (NEW -> INVESTIGATING -> RESOLVED)
    print("\n[2/10] Auditing Alert Lifecycle State Transitions...")
    updated_inv = alert_center_engine.update_alert_status("ALT-001", AlertStatusEnum.INVESTIGATING)
    assert updated_inv.status == AlertStatusEnum.INVESTIGATING
    print(f"    ALT-001 transitioned to: {updated_inv.status.value}")

    updated_res = alert_center_engine.update_alert_status("ALT-001", AlertStatusEnum.RESOLVED)
    assert updated_res.status == AlertStatusEnum.RESOLVED
    print(f"    ALT-001 transitioned to: {updated_res.status.value}")
    print("    [PASS] Lifecycle status transition verified.")

    # 3. 8-Tier Alert Drill-Down Dossier
    print("\n[3/10] Auditing 8-Tier Investigative Drill-Down Synthesis...")
    dossier = alert_center_engine.get_8tier_drilldown("ALT-004")

    print(f"    1. Alert        : {dossier.alert.alertId} ({dossier.alert.eventType})")
    print(f"    2. Event        : {dossier.eventContext['rawEventId']}")
    print(f"    3. Features     : {list(dossier.featureVector.keys())}")
    print(f"    4. Detection    : {dossier.detectionDetails['source']} ({dossier.detectionDetails['confidenceScore']})")
    print(f"    5. ML Predict   : {dossier.mlPrediction['predictedCategory']}")
    print(f"    6. XAI SHAP     : {dossier.xaiAttribution['primaryFactor']}")
    print(f"    7. Risk         : {dossier.riskBreakdown['compositeRisk']} ({dossier.riskBreakdown['assetCriticality']})")
    print(f"    8. Attack Path  : {' -> '.join(dossier.attackPathTrajectory['traversedRoute'])}")

    assert dossier.alert.alertId == "ALT-004"
    assert "connection_frequency" in dossier.featureVector
    assert dossier.attackPathTrajectory["reachability"] == "REACHABLE"
    print("    [PASS] Full 8-tier alert drill-down validated.")

    # 4. Multi-Alert Incident Campaign Correlation
    print("\n[4/10] Auditing Multi-Alert Incident Campaign Correlation...")
    campaigns = alert_center_engine.campaigns
    assert len(campaigns) >= 1
    c = campaigns[0]

    print(f"    Campaign ID    : {c.campaignId}")
    print(f"    Campaign Name  : {c.campaignName}")
    print(f"    Involved Alerts: {c.involvedAlertIds}")
    print(f"    Hosts Scope    : {c.participatingDevices}")
    print(f"    Max Severity   : {c.maxSeverity.value} (Risk: {c.aggregateRiskScore})")

    assert len(c.involvedAlertIds) == 3
    assert "CLIENT-01" in c.participatingDevices
    assert "DB-01" in c.participatingDevices
    print("    [PASS] Correlated security activity fused successfully.")

    # 5. Severity Filtering
    print("\n[5/10] Auditing Alert Filtering by Severity (CRITICAL)...")
    crit_alerts = alert_center_engine.filter_alerts(AlertFilterCriteria(severity=RiskLevelTier.CRITICAL))
    print(f"    Matched Critical Alerts: {[a.alertId for a in crit_alerts]}")
    assert len(crit_alerts) == 1
    assert crit_alerts[0].severity == RiskLevelTier.CRITICAL
    print("    [PASS] Severity filtering verified.")

    # 6. Status Filtering
    print("\n[6/10] Auditing Alert Filtering by Status (NEW)...")
    new_alerts = alert_center_engine.filter_alerts(AlertFilterCriteria(status=AlertStatusEnum.NEW))
    print(f"    Matched NEW Alerts: {[a.alertId for a in new_alerts]}")
    assert all(a.status == AlertStatusEnum.NEW for a in new_alerts)
    print("    [PASS] Status filtering verified.")

    # 7. Operational Alert Counters
    print("\n[7/10] Auditing Alert Metric Counters (New, Investigating, High, Critical)...")
    counters = alert_center_engine.get_alert_counters()
    print(f"    Counters: NEW={counters.newAlerts}, INV={counters.investigatingAlerts}, HIGH={counters.highSeverityAlerts}, CRIT={counters.criticalSeverityAlerts}")
    assert counters.totalActive >= 4
    assert counters.criticalSeverityAlerts >= 1
    assert counters.highSeverityAlerts >= 1
    print("    [PASS] Alert counters verified.")

    # 8. Duplicate Alert Suppression
    print("\n[8/10] Auditing Duplicate Alert Suppression...")
    count_before = len(alert_center_engine.alerts)
    dup = alert_center_engine.alerts[0].model_copy()
    alert_center_engine.create_alert(dup)
    assert len(alert_center_engine.alerts) == count_before
    print("    [PASS] Duplicate alert ingestion suppressed.")

    # 9. Defensive Validation on Missing/Invalid Timestamp
    print("\n[9/10] Auditing Defensive Validation on Invalid Alert Timestamp...")
    invalid_caught = False
    try:
        SecurityAlertItem(
            timestamp="",
            severity=RiskLevelTier.LOW,
            sourceDevice="DEV-A",
            destinationDevice="DEV-B",
            eventType="FAIL_ALERT",
            detectionSource=DetectionSourceEnum.SIMULATION,
            confidence=0.8,
            riskScore=10.0
        )
    except ValueError as e:
        invalid_caught = True
        print(f"    Trapped Invalid Timestamp: {e}")
    assert invalid_caught
    print("    [PASS] Invalid alert timestamp trapped.")

    # 10. Missing Event / Alert Error Trapping
    print("\n[10/10] Auditing Missing Alert ID Error Trapping...")
    missing_caught = False
    try:
        alert_center_engine.get_8tier_drilldown("NON-EXISTENT-ALT")
    except KeyError as e:
        missing_caught = True
        print(f"    Trapped Missing Alert ID: {e}")
    assert missing_caught
    print("    [PASS] Non-existent alert trapped cleanly.")

    # Reset environment
    alert_center_engine._seed_default_alerts()

    print("\n" + "=" * 80)
    print("       ALL DAY 150 ALERT CENTER TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day150_suite()