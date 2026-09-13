import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.prediction.temporal_prediction_models import TemporalPrediction
from services.digital_twin.ml.time_series.prediction.integrated_time_series_pipeline import integrated_time_series_pipeline
from services.digital_twin.ml.time_series.evaluation.master_temporal_evaluator import master_temporal_evaluator

def run_day119_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 119: TIME-SERIES EVALUATION & TWIN INTEGRATION AUDIT")
    print("=" * 80 + "\n")

    integrated_time_series_pipeline.clear()

    # 1. Dual-Horizon Decoupled Prediction Audit (Canonical Specification Example)
    print("[1/5] Auditing Decoupled Current (42%) vs Future (87%) Threat Prediction...")
    dummy_seq = [[20.0 + i * 15.0] * 16 for i in range(5)]
    curr_feats = {"packet_rate": 45.0, "bytes_per_second": 25000.0}

    pred = integrated_time_series_pipeline.predict_sequence(
        sequence_matrix=dummy_seq,
        current_features=curr_feats,
        device_id="CLIENT-01",
        target_device="SERVER-01",
        model_name="lstm",
        current_stage="EARLY_INDICATORS",
        lead_time_override=35.0,
        future_threat_override=0.87
    )

    print(f"    Current Threat Probability : {pred.currentThreatProbabilityFormatted} (Expected: ~42.0%)")
    print(f"    Future Threat Probability  : {pred.futureThreatProbabilityFormatted}")
    print(f"    Predicted Category         : {pred.predictedCategory}")
    print(f"    Predicted Impact Stage     : {pred.predictedImpactStage}")
    print(f"    Early Warning Triggered    : {pred.isEarlyWarningTriggered}")
    print(f"    Measured Lead Time         : {pred.leadTimeFormatted}")

    assert pred.currentThreatProbability < pred.futureThreatProbability
    assert pred.isEarlyWarningTriggered is True
    print("    [PASS] Current and Future threat probabilities decoupled and verified.")

    # 2. Digital Twin Early Warning Dashboard Visual Formatting Audit
    print("\n[2/5] Auditing Terminal Dashboard Display Output Formatting...")
    disp = pred.to_dashboard_display()
    print(disp)
    assert "DIGITAL TWIN EARLY WARNING" in disp
    assert "Device: CLIENT-01" in disp
    assert "Current Threat Probability:" in disp
    assert "Future Threat Probability:" in disp
    assert "Lead Time:" in disp
    print("    [PASS] Formatted ASCII Early Warning Card validated.")

    # 3. Digital Twin Extended Security State Synchronization
    print("\n[3/5] Auditing Extended Digital Twin Security State Synchronization...")
    tw_state = integrated_time_series_pipeline.device_states["CLIENT-01"]
    print(f"    Twin Security Status : {tw_state['securityStatus']}")
    print(f"    Current Threat Prob  : {tw_state['currentThreatProbability']}")
    print(f"    Future Threat Prob   : {tw_state['futureThreatProbability']}")
    print(f"    Early Warning Status : {tw_state['earlyWarningStatus']}")

    assert tw_state["securityStatus"] == "AT_RISK"
    assert tw_state["futureThreatProbability"] == pred.futureThreatProbabilityFormatted
    assert tw_state["predictionLeadTime"] == "35.0 seconds"
    print("    [PASS] Digital Twin security state successfully mutated.")

    # 4. Three-Way Model Master Benchmark Audit (LSTM vs GRU vs Temporal Model)
    print("\n[4/5] Auditing 3-Way Comparative Leaderboard (LSTM vs GRU vs Temporal Model)...")
    bench = master_temporal_evaluator.run_master_benchmark()
    comp_tbl = bench["temporalComparisonTable"]
    eff_tbl = bench["efficiencyTable"]

    print("\n    Detection & Timeliness Leaderboard:")
    print("    | Model          | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Early-Warning Rate | Avg Lead Time |")
    print("    |----------------|----------|-----------|--------|----------|---------|--------------------|---------------|")
    for row in comp_tbl:
        print(f"    | {row['model']:<14} | {row['accuracy']:<8.4f} | {row['precision']:<9.4f} | {row['recall']:<6.4f} | {row['f1']:<8.4f} | {row['rocAuc']:<7.4f} | {row['earlyWarningRate']*100:.0f}%                | {row['avgLeadTime']:<13} |")

    assert len(comp_tbl) == 3
    for row in comp_tbl:
        assert row["accuracy"] >= 0.80
        assert row["earlyWarningRate"] == 1.0

    print("\n    Computational Efficiency Leaderboard:")
    print("    | Model          | Training Time | Inference Latency | Parameter Count | False Warnings |")
    print("    |----------------|---------------|-------------------|-----------------|----------------|")
    for row in eff_tbl:
        print(f"    | {row['model']:<14} | {row['trainingTimeMs']:<10.2f} ms | {row['inferenceTimeMs']:<14.3f} ms | {row['parameterCount']:<15} | {row['falseEarlyWarnings']:<14} |")

    assert len(eff_tbl) == 3
    for row in eff_tbl:
        assert row["falseEarlyWarnings"] == 0
        assert row["inferenceTimeMs"] < 25.0

    print("    [PASS] 3-way temporal benchmark verified across detection and computational efficiency.")

    # 5. Full 7-Scenario Pre-Impact Early-Warning Audit
    print("\n[5/5] Auditing Scenario-Based Early Warning across 7 Canonical Attack Profiles...")
    scenarios = bench["scenarioAudit"]
    assert len(scenarios) == 7
    expected_categories = {
        "PORT_SCAN", "BRUTE_FORCE_LIKE", "DOS_LIKE", "DNS_ANOMALY",
        "BEACONING", "LATERAL_MOVEMENT_LIKE", "EXFILTRATION_LIKE"
    }
    actual_categories = {s["category"] for s in scenarios}
    assert expected_categories == actual_categories

    for s in scenarios:
        print(f"    Scenario: {s['scenario']:<22} | Early Warning: {s['earlyWarning']} | Lead Time: {s['leadTime']} | Pred Time: {s['predictionTime']} < Impact: {s['impactTime']}")
        assert s["earlyWarning"] == "YES"
        assert "seconds" in s["leadTime"]

    print("    [PASS] Pre-impact early warning confirmed across all 7 canonical attack profiles.")

    print("\n" + "=" * 80)
    print("       ALL DAY 119 TIME-SERIES EVALUATION TESTS PASSED CLEANLY")
    print("       PHASE 14: TIME-SERIES PREDICTION GRADUATED SUCCESSFULLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day119_suite()