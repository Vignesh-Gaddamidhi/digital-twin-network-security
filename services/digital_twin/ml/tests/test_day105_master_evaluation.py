import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.evaluation.master_evaluation_engine import master_evaluation_engine

def run_day105_suite():
    print("=" * 80)
    print("       WEEK 15 - DAY 105: MASTER EVALUATION & BENCHMARK AUDIT")
    print("=" * 80 + "\n")

    # 1. Complete Multi-Model Master Run
    print("[1/6] Executing Unified Master Evaluation Across All 5 Baselines...")
    report = master_evaluation_engine.run_master_evaluation()

    assert report["modelsEvaluated"] == 5
    assert "bestBaseline" in report
    print(f"    Total Models Evaluated: {report['modelsEvaluated']}")
    print(f"    Selected Best Baseline : {report['bestBaseline']}")
    print("    [PASS] All 5 models trained and evaluated.")

    # 2. Metrics & Leaderboard Verification
    print("\n[2/6] Auditing Master Comparison Table Values...")
    leaderboard = report["leaderboard"]
    print("\n    | Rank | Model                  | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Score  |")
    print("    |------|------------------------|----------|-----------|--------|----------|---------|--------|")
    for row in leaderboard:
        auc_str = f"{row['rocAuc']:.4f}" if row.get("rocAuc") is not None else "N/A"
        print(f"    | {row['rank']:<4} | {row['modelName']:<22} | {row['accuracy']:<8.4f} | {row['precision']:<9.4f} | {row['recall']:<6.4f} | {row['f1Score']:<8.4f} | {auc_str:<7} | {row['cyberScore']:<6.4f} |")

    assert len(leaderboard) == 5
    expected_models = {"Logistic Regression", "Decision Tree", "Random Forest", "Support Vector Machine", "XGBoost"}
    actual_models = {r["modelName"] for r in leaderboard}
    assert expected_models == actual_models
    print("    [PASS] Complete metrics table validated without missing models.")

    # 3. Independent Confusion Matrix for EVERY Model
    print("\n[3/6] Auditing Confusion Matrix and Error Distribution for Every Model...")
    for r in leaderboard:
        cm = r["confusionMatrix"]
        assert len(cm) == 2 and len(cm[0]) == 2 and len(cm[1]) == 2
        tn, fp = cm[0][0], cm[0][1]
        fn, tp = cm[1][0], cm[1][1]

        assert tn == r["trueNegatives"]
        assert fp == r["falsePositives"]
        assert fn == r["falseNegatives"]
        assert tp == r["truePositives"]
        assert (tp + fp + tn + fn) == report["testSamples"]
        print(f"    - {r['modelName']:<22}: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print("    [PASS] Independent 2x2 confusion matrices verified for all 5 models.")

    # 4. False Positive & False Negative Risk Diagnostics
    print("\n[4/6] Auditing False Positive & False Negative Security Trade-offs...")
    recs = report["operationalRecommendations"]
    print(f"    Highest Recall (Least Missed Attacks): {recs['highestRecall']}")
    print(f"    Lowest False Alerts (Least Fatigue)  : {recs['lowestFalseAlerts']}")
    print(f"    Fastest Inference Latency            : {recs['fastestInference']}")
    assert recs["highestRecall"] in expected_models
    print("    [PASS] Operational recommendations successfully synthesized.")

    # 5. Persistent Artifact Verification (CSV, JSON, PNGs)
    print("\n[5/6] Auditing File System Persistence (CSV, JSON, PNG Images)...")
    comp_dir = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "comparison"
    cm_dir = comp_dir / "confusion_matrices"

    assert (comp_dir / "model_comparison.csv").exists()
    assert (comp_dir / "model_comparison.json").exists()
    assert (comp_dir / "report.json").exists()

    png_keys = ["logistic_regression", "decision_tree", "random_forest", "svm", "xgboost"]
    for pk in png_keys:
        png_file = cm_dir / f"{pk}.png"
        assert png_file.exists(), f"Missing confusion matrix image: {png_file}"
        assert png_file.stat().st_size > 1000
    print("    [PASS] CSV, JSON reports, and all 5 PNG confusion matrices persisted.")

    # 6. Deterministic Reproducibility Audit
    print("\n[6/6] Auditing Reproducibility Across Dual Execution Passes...")
    reproducible = master_evaluation_engine.test_reproducibility()
    assert reproducible is True
    print("    [PASS] Bitwise reproducibility verified across independent pipeline evaluations.")

    print("\n" + "=" * 80)
    print("       ALL DAY 105 MASTER EVALUATION TESTS PASSED CLEANLY")
    print("       WEEK 15: BASELINE MACHINE LEARNING MODELS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_day105_suite()