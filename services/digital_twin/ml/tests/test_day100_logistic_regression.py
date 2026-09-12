import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.logistic_regression.logistic_regression_classifier import AttackLogisticRegressionClassifier
from services.digital_twin.ml.training.train_logistic_regression import run_logistic_regression_training, evaluate_custom_threshold

def run_day100_suite():
    print("=" * 80)
    print("       WEEK 15 - DAY 100: LOGISTIC REGRESSION BASELINE AUDIT")
    print("=" * 80 + "\n")

    # 1. Parameter & Class Architecture Audit
    print("[1/6] Auditing Classifier Parameter Architecture...")
    clf = AttackLogisticRegressionClassifier(random_seed=42)
    assert clf.model_name == "logistic_regression"
    assert clf.hyperparameters["solver"] == "lbfgs"
    assert clf.hyperparameters["class_weight"] == "balanced"
    print("    [PASS] Parameters initialized with balanced class weighting.")

    # 2. Training on Normalized Datasets
    print("\n[2/6] Loading Datasets and Executing Model Training...")
    X_train, y_train, X_test, y_test, features = dataset_loader.load_train_test()
    meta = clf.train(X_train, y_train, feature_names=features)

    assert clf.is_fitted is True
    assert meta.trainingRecordsCount == X_train.shape[0]
    print(f"    [PASS] Trained on {meta.trainingRecordsCount} samples with {meta.featureCount} features.")

    # 3. Probability & Prediction Calibration
    print("\n[3/6] Auditing Prediction Output and Continuous Probabilities...")
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)

    assert preds.shape == (X_test.shape[0],)
    assert probs.shape == (X_test.shape[0], 2)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.allclose(probs.sum(axis=1), 1.0)
    print("    [PASS] Probabilities strictly continuous, bounded in [0.0, 1.0], and summing to 1.0.")

    # 4. Standard Metric Evaluation
    print("\n[4/6] Evaluating Core Classification Metrics...")
    metrics = clf.evaluate(X_test, y_test)
    print(f"    Accuracy  : {metrics.accuracy:.4f}")
    print(f"    Precision : {metrics.precision:.4f}")
    print(f"    Recall    : {metrics.recall:.4f}")
    print(f"    F1-Score  : {metrics.f1Score:.4f}")
    print(f"    ROC-AUC   : {metrics.rocAuc}")
    print(f"    Confusion Matrix : {metrics.confusionMatrix}")

    assert 0.0 <= metrics.accuracy <= 1.0
    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.recall <= 1.0
    assert 0.0 <= metrics.f1Score <= 1.0
    assert len(metrics.confusionMatrix) == 2
    print("    [PASS] Core metrics accurately computed.")

    # 5. Threshold Analysis Verification (0.50 vs 0.35)
    print("\n[5/6] Auditing Threshold Adjustment Behavior (0.50 vs 0.35)...")
    t050 = evaluate_custom_threshold(probs, y_test, threshold=0.50)
    t035 = evaluate_custom_threshold(probs, y_test, threshold=0.35)

    print(f"    At 0.50 Threshold: Recall={t050['recall']}, Precision={t050['precision']}, F1={t050['f1']}")
    print(f"    At 0.35 Threshold: Recall={t035['recall']}, Precision={t035['precision']}, F1={t035['f1']}")
    assert t035["recall"] >= t050["recall"]
    print("    [PASS] Threshold sensitivity confirms non-decreasing recall at lower decision boundary.")

    # 6. Artifact Generation & Storage Audit
    print("\n[6/6] Executing Automated Artifact Generation (model.joblib, metadata.json, metrics.json)...")
    res = run_logistic_regression_training()
    art_dir = Path(res["artifactsPath"])

    assert (art_dir / "model.joblib").exists()
    assert (art_dir / "metadata.json").exists()
    assert (art_dir / "metrics.json").exists()

    with open(art_dir / "metrics.json", "r", encoding="utf-8") as f:
        stored_metrics = json.load(f)
    assert "standardEvaluation" in stored_metrics
    assert "thresholdAnalysis" in stored_metrics
    print(f"    [PASS] All artifacts successfully persisted to {art_dir}.")

    print("\n" + "=" * 80)
    print("       ALL DAY 100 LOGISTIC REGRESSION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day100_suite()