import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from frontend.predictions.early_warning_models import EarlyWarningStateEnum
from frontend.predictions.early_warning_engine import early_warning_dashboard_engine

def run_day152_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 152: TIME-SERIES EARLY-WARNING DASHBOARD AUDIT")
    print("=" * 80 + "\n")

    early_warning_dashboard_engine._seed_default_state()

    # 1. Snapshot Generation & Dual Horizon
    print("[1/8] Auditing Early Warning Snapshot Generation & Dual Horizon...")
    snap = early_warning_dashboard_engine.generate_snapshot("WEB-01", current_prob=0.72, future_prob=0.87, horizon_sec=60, lead_time_sec=42)
    card_str = snap.render_cli_card()
    print(card_str)

    assert snap.currentThreatProbability == 0.72
    assert snap.futureThreatProbability == 0.87
    assert snap.predictionHorizonSeconds == 60
    assert snap.leadTimeSeconds == 42
    assert snap.status == EarlyWarningStateEnum.HIGH_CONFIDENCE_WARNING
    print("    [PASS] Early warning card generated with dual-horizon metrics.")

    # 2. Warning State Threshold Traversal
    print("\n[2/8] Auditing Warning State Threshold Traversal...")
    states_to_test = [
        (0.20, 0.50, EarlyWarningStateEnum.NO_WARNING),
        (0.60, 0.80, EarlyWarningStateEnum.WATCH),
        (0.78, 0.80, EarlyWarningStateEnum.EARLY_WARNING),
        (0.88, 0.88, EarlyWarningStateEnum.HIGH_CONFIDENCE_WARNING),
        (0.95, 0.95, EarlyWarningStateEnum.IMPACT_STAGE)
    ]
    for p_fut, conf, expected in states_to_test:
        st = early_warning_dashboard_engine.determine_warning_state(p_fut, conf)
        print(f"    Prob={p_fut*100:4.1f}% Conf={conf*100:4.1f}% -> State: {st.value:<23} (Expected: {expected.value})")
        assert st == expected
    print("    [PASS] All 5 early-warning state thresholds verified.")

    # 3. Lead-Time Calculation
    print("\n[3/8] Auditing Lead-Time to Modeled Impact (42s Window)...")
    assert snap.leadTimeSeconds == 42
    print(f"    Lead-Time Recorded: {snap.leadTimeSeconds} seconds prior to simulated impact.")
    print("    [PASS] Lead-time metric verified.")

    # 4. Temporal Model Ensemble Comparison (LSTM, GRU, Temporal)
    print("\n[4/8] Auditing Model Ensemble Comparison (LSTM, GRU, Temporal)...")
    models = {m.modelName: m.futureThreatProbability for m in snap.modelComparisons}
    print(f"    Ensemble Output: {models}")
    assert "LSTM" in models
    assert "GRU" in models
    assert "Temporal" in models
    assert models["LSTM"] == 0.87
    assert models["GRU"] == 0.84
    assert models["Temporal"] == 0.81
    print("    [PASS] Multi-model architecture comparison validated.")

    # 5. Warning History Ledger & Consecutive Counters
    print("\n[5/8] Auditing Warning History & Consecutive Counter Ingestion...")
    snap_hist = early_warning_dashboard_engine.generate_snapshot("WEB-01", future_prob=0.88)
    active_rec = snap_hist.warningHistory[0]
    print(f"    Target: {active_rec.targetDevice} | Consecutive Counter: {active_rec.consecutiveWarningCount}")
    assert active_rec.consecutiveWarningCount >= 2
    print("    [PASS] Consecutive warning progression recorded.")

    # 6. Cooldown Trigger & Suppression
    print("\n[6/8] Auditing Warning Cooldown Suppression Logic...")
    early_warning_dashboard_engine.trigger_cooldown("WEB-01", duration_sec=45)
    rec_cool = early_warning_dashboard_engine.active_history[0]
    print(f"    Cooldown Remaining: {rec_cool.cooldownRemainingSec}s")
    assert rec_cool.cooldownRemainingSec == 45
    print("    [PASS] Cooldown timer set and enforced.")

    # 7. False Warning / Noise Suppression
    print("\n[7/8] Auditing Noise / Low-Probability Warning Suppression...")
    snap_noise = early_warning_dashboard_engine.generate_snapshot("DNS-SERVER-01", current_prob=0.10, future_prob=0.15)
    print(f"    Low Probability State: {snap_noise.status.value}")
    assert snap_noise.status == EarlyWarningStateEnum.NO_WARNING
    print("    [PASS] Low-threat telemetry does not trigger false warnings.")

    # 8. Defensive Validation of Invalid Probabilities
    print("\n[8/8] Auditing Defensive Validation on Out-of-Bounds Forecasts...")
    trapped = False
    try:
        early_warning_dashboard_engine.generate_snapshot("WEB-01", current_prob=1.5, future_prob=0.5)
    except ValueError as e:
        trapped = True
        print(f"    Trapped Out-of-Bounds Probability: {e}")
    assert trapped
    print("    [PASS] Invalid forecast probability rejected defensively.")

    print("\n" + "=" * 80)
    print("       ALL DAY 152 EARLY-WARNING DASHBOARD TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day152_suite()