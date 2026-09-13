import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.models.temporal.tcn_model import TemporalConvPredictor
from services.digital_twin.ml.time_series.early_warning.early_warning_engine import early_warning_engine, EarlyWarningState
from services.digital_twin.ml.time_series.sequences.sequence_dataset_builder import sequence_dataset_builder
from services.digital_twin.ml.time_series.windows.window_models import SlidingWindowConfig

def run_day118_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 118: TEMPORAL CONVOLUTION & EARLY-WARNING ENGINE AUDIT")
    print("=" * 80 + "\n")

    early_warning_engine.clear()

    # 1. Temporal 1D Convolution (TCN) Model Audit
    print("[1/5] Auditing 1D Temporal Convolutional Predictor (TCN)...")
    cfg = SlidingWindowConfig(windowSize=5, stepSize=1, predictionHorizon=3, featureDim=16)
    dataset = sequence_dataset_builder.build_dataset(config=cfg)

    tcn = TemporalConvPredictor(input_dim=16, kernel_size=3, filters=32, random_seed=42)
    param_count = tcn.count_parameters()
    print(f"    TCN Total Parameter Count: {param_count}")
    assert param_count > 0

    train_res = tcn.fit(dataset["X_train"], dataset["y_train"])
    eval_res = tcn.evaluate(dataset["X_test"], dataset["y_test"])
    print(f"    TCN Training Epochs : {train_res['epochsTrained']}")
    print(f"    TCN Test Accuracy   : {eval_res['accuracy']:.4f}")
    print(f"    TCN Test F1-Score   : {eval_res['f1']:.4f}")

    assert eval_res["accuracy"] >= 0.80
    assert eval_res["f1"] >= 0.80
    print("    [PASS] TCN baseline trained and evaluated successfully.")

    # 2. Early-Warning Operational States Audit
    print("\n[2/5] Auditing Early-Warning State Machine Transitions...")
    # Test state mapping
    assert early_warning_engine.evaluate_warning_state(0.20, "NORMAL") == EarlyWarningState.NO_WARNING
    assert early_warning_engine.evaluate_warning_state(0.50, "NORMAL") == EarlyWarningState.WATCH
    assert early_warning_engine.evaluate_warning_state(0.72, "EARLY_INDICATORS") == EarlyWarningState.EARLY_WARNING
    assert early_warning_engine.evaluate_warning_state(0.91, "ESCALATION") == EarlyWarningState.HIGH_CONFIDENCE_WARNING
    assert early_warning_engine.evaluate_warning_state(0.95, "IMPACT") == EarlyWarningState.IMPACT_STAGE
    print("    [PASS] All 5 early-warning operational states verified.")

    # 3. Anti-Flooding Aggregator Audit (72% -> 73% -> 71% -> 74% -> 73%)
    print("\n[3/5] Auditing Alert Anti-Flooding Suppression...")
    probabilities = [0.72, 0.73, 0.71, 0.74, 0.73]
    alert_counts = 0

    for idx, prob in enumerate(probabilities):
        rec, is_new = early_warning_engine.process_prediction(
            device_id="CORE-ROUTER",
            threat_probability=prob,
            current_stage="EARLY_INDICATORS",
            predicted_category="DOS_LIKE",
            lead_time_seconds=35.0
        )
        if is_new:
            alert_counts += 1
        print(f"    Injected Prob {prob*100:.0f}% -> Is New Alert: {is_new} | Consecutive: {rec.consecutiveDetections}")

    # Anti-flooding invariant: Only the first detection triggers a new alert; subsequent detections aggregate
    assert alert_counts == 1
    assert rec.consecutiveDetections == 5
    assert rec.peakThreatProbability == 0.74
    assert rec.state == EarlyWarningState.EARLY_WARNING
    print("    [PASS] Anti-flooding verified: 5 high-threat events aggregated into 1 active warning.")

    # 4. Pre-Impact Lead Time Ground Truth
    print("\n[4/5] Auditing Pre-Impact Warning Timing...")
    rec_esc, is_new_esc = early_warning_engine.process_prediction(
        device_id="CORE-ROUTER",
        threat_probability=0.91,
        current_stage="ESCALATION"
    )
    print(f"    Escalation Stage State: {rec_esc.state.value}")
    print(f"    Lead Time Runway      : {rec_esc.leadTimeEstimateSeconds} seconds")

    assert rec_esc.state == EarlyWarningState.HIGH_CONFIDENCE_WARNING
    assert rec_esc.leadTimeEstimateSeconds > 0.0
    print("    [PASS] High-confidence warning issued prior to impact stage.")

    # 5. Persistent Artifact Verification
    print("\n[5/5] Auditing Warning Record Persistence on Disk...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "early_warning" / "warning_records.json"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        stored_records = json.load(f)
    assert len(stored_records) > 0
    target_rec = stored_records[-1]
    assert target_rec["deviceId"] == "CORE-ROUTER"
    assert target_rec["consecutiveDetections"] == 6
    print(f"    Persisted Warning Record ID: {target_rec['warningId']}")
    print("    [PASS] Warning record verified in warning_records.json.")

    print("\n" + "=" * 80)
    print("       ALL DAY 118 EARLY-WARNING ENGINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day118_suite()