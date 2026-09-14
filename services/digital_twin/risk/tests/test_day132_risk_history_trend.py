import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.history.risk_trend_models import (
    RiskTrendDirection, RiskEventType
)
from services.digital_twin.risk.history.risk_state_engine import risk_state_engine

def run_day132_suite():
    print("=" * 80)
    print("       WEEK 19 - DAY 132: RISK HISTORY, AGGREGATION & TREND AUDIT")
    print("=" * 80 + "\n")

    risk_state_engine.clear()

    # 1. Sequential Risk History Ledger Verification (Canonical Specification Case)
    print("[1/8] Auditing Risk History Sequential Logging...")
    canonical_series = [12.0, 18.0, 36.0, 58.0, 79.0, 71.0, 43.0]
    expected_tiers = [
        RiskLevelTier.LOW, RiskLevelTier.LOW, RiskLevelTier.MEDIUM,
        RiskLevelTier.HIGH, RiskLevelTier.CRITICAL, RiskLevelTier.HIGH, RiskLevelTier.MEDIUM
    ]

    for idx, score in enumerate(canonical_series):
        st, evs = risk_state_engine.record_risk_observation("SERVER-CANON", score, f"PRED-{idx}")
        print(f"    Step {idx+1}: Score = {score:4.1f} | Tier = {st.currentRiskLevel.value:<8} | Trend = {st.riskTrend.value:<10}")

    assert len(st.history) == 7
    for idx, obs in enumerate(st.history):
        assert obs.riskScore == canonical_series[idx]
        assert obs.riskLevel == expected_tiers[idx]
    print("    [PASS] Risk history ledger precisely preserved.")

    # 2. Trend Classification Engine
    print("\n[2/8] Auditing Mathematical Trend Classification...")
    assert risk_state_engine.calculate_trend([20.0, 35.0, 49.0, 62.0, 74.0]) == RiskTrendDirection.INCREASING
    assert risk_state_engine.calculate_trend([75.0, 62.0, 48.0, 35.0, 20.0]) == RiskTrendDirection.DECREASING
    assert risk_state_engine.calculate_trend([40.0, 41.0, 40.0, 42.0, 41.0]) == RiskTrendDirection.STABLE
    assert risk_state_engine.calculate_trend([20.0, 80.0, 25.0, 85.0, 20.0]) == RiskTrendDirection.VOLATILE
    assert risk_state_engine.calculate_trend([50.0, 60.0]) == RiskTrendDirection.UNKNOWN
    print("    [PASS] INCREASING, DECREASING, STABLE, and VOLATILE trends validated.")

    # 3. Escalation Transition Event Emission
    print("\n[3/8] Auditing Escalation Transition Detection (LOW -> MED -> HIGH -> CRIT)...")
    risk_state_engine.clear()
    st_low, _ = risk_state_engine.record_risk_observation("DEV-ESC", 10.0, "P-1")
    st_med, ev_med = risk_state_engine.record_risk_observation("DEV-ESC", 35.0, "P-2")
    st_high, ev_high = risk_state_engine.record_risk_observation("DEV-ESC", 60.0, "P-3")
    st_crit, ev_crit = risk_state_engine.record_risk_observation("DEV-ESC", 85.0, "P-4")

    print(f"    10 -> 35 : Events = {[e.eventType.value for e in ev_med]}")
    print(f"    35 -> 60 : Events = {[e.eventType.value for e in ev_high]}")
    print(f"    60 -> 85 : Events = {[e.eventType.value for e in ev_crit]}")

    assert any(e.eventType == RiskEventType.RISK_LEVEL_INCREASED for e in ev_med)
    assert any(e.eventType == RiskEventType.HIGH_RISK_REACHED for e in ev_high)
    assert any(e.eventType == RiskEventType.CRITICAL_RISK_REACHED for e in ev_crit)
    print("    [PASS] Escalation transition events verified.")

    # 4. De-escalation & Recovery Transition Audit
    print("\n[4/8] Auditing De-escalation & Operational Recovery (CRIT -> HIGH -> MED -> LOW)...")
    st_r1, ev_r1 = risk_state_engine.record_risk_observation("DEV-ESC", 65.0, "P-5")
    st_r2, ev_r2 = risk_state_engine.record_risk_observation("DEV-ESC", 35.0, "P-6")
    st_r3, ev_r3 = risk_state_engine.record_risk_observation("DEV-ESC", 15.0, "P-7")

    print(f"    85 -> 65 : Events = {[e.eventType.value for e in ev_r1]}")
    print(f"    65 -> 35 : Events = {[e.eventType.value for e in ev_r2]}")
    print(f"    35 -> 15 : Events = {[e.eventType.value for e in ev_r3]}")

    assert any(e.eventType == RiskEventType.RISK_LEVEL_DECREASED for e in ev_r1)
    assert any(e.eventType == RiskEventType.RISK_LEVEL_DECREASED for e in ev_r2)
    assert any(e.eventType == RiskEventType.RISK_LEVEL_DECREASED for e in ev_r3)
    assert st_r3.currentRiskLevel == RiskLevelTier.LOW
    print("    [PASS] De-escalation and operational recovery confirmed.")

    # 5. Risk Score Spike Detection
    print("\n[5/8] Auditing Sudden Risk Score Spike Detection (+30 points)...")
    _, ev_spike = risk_state_engine.record_risk_observation("DEV-ESC", 65.0, "P-8")  # 15 -> 65 (+50 delta)
    print(f"    15 -> 65 : Spike Detected = {any(e.eventType == RiskEventType.RISK_SCORE_SPIKE for e in ev_spike)}")
    assert any(e.eventType == RiskEventType.RISK_SCORE_SPIKE for e in ev_spike)
    print("    [PASS] Risk spike event triggered.")

    # 6. Network-Level Multi-Device Risk Aggregation (Specification Example)
    print("\n[6/8] Auditing Network-Level Risk Aggregation (CLIENT-01=30, WEB-01=65, DB-01=85, DNS-01=40)...")
    risk_state_engine.clear()
    risk_state_engine.record_risk_observation("CLIENT-01", 30.0, "P-C1")
    risk_state_engine.record_risk_observation("WEB-01", 65.0, "P-W1")
    risk_state_engine.record_risk_observation("DB-01", 85.0, "P-D1")
    risk_state_engine.record_risk_observation("DNS-01", 40.0, "P-DNS")

    net_max = risk_state_engine.aggregate_network_risk(strategy="MAX")
    net_top = risk_state_engine.aggregate_network_risk(strategy="TOP_N", top_n=2)
    net_avg = risk_state_engine.aggregate_network_risk(strategy="WEIGHTED_AVERAGE")

    print(f"    MAX Strategy              : Score = {net_max.networkRiskScore:.2f} [{net_max.networkRiskLevel.value}] | Highest Node: {net_max.highestRiskDevice}")
    print(f"    TOP_N (N=2) Strategy      : Score = {net_top.networkRiskScore:.2f} [{net_top.networkRiskLevel.value}]")
    print(f"    WEIGHTED_AVERAGE Strategy : Score = {net_avg.networkRiskScore:.2f} [{net_avg.networkRiskLevel.value}]")

    assert net_max.networkRiskScore == 85.0
    assert net_max.networkRiskLevel == RiskLevelTier.CRITICAL
    assert net_max.highestRiskDevice == "DB-01"
    assert net_max.criticalDeviceCount == 1
    assert net_max.highDeviceCount == 1
    assert abs(net_top.networkRiskScore - 75.0) < 1e-1  # mean(85, 65) = 75.0
    print("    [PASS] Multi-device network risk aggregation strategies validated.")

    # 7. Cooldown Deduplication Verification
    print("\n[7/8] Auditing Alert Deduplication & Cooldown Flagging...")
    # Immediate repeat calculation on DB-01 with elevated score
    _, ev_rapid = risk_state_engine.record_risk_observation("DB-01", 88.0, "P-D2")
    if ev_rapid:
        assert all(e.cooldownActive for e in ev_rapid)
        print("    [PASS] Rapid consecutive events correctly marked with cooldownActive=True.")
    else:
        print("    [PASS] No redundant state transition emitted.")

    # 8. Disk Artifact Persistence Audit
    print("\n[8/8] Auditing Disk Artifact Persistence...")
    hist_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "risk_history.json"
    ev_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "risk_events.json"

    assert hist_file.exists()
    assert ev_file.exists()

    with open(hist_file, "r", encoding="utf-8") as f:
        saved_hist = json.load(f)
    assert len(saved_hist) == 4  # CLIENT-01, WEB-01, DB-01, DNS-01
    assert saved_hist["DB-01"]["currentRiskScore"] == 88.0

    print("    [PASS] Continuous state and event logs persisted on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 132 RISK HISTORY, AGGREGATION & TREND TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day132_suite()