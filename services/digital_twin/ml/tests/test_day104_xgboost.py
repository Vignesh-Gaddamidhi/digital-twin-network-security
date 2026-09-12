import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.xgboost.xgboost_classifier import AttackXGBoostClassifier
from services.digital_twin.ml.training.train_xgboost import run_xgboost_training
from services.digital_twin.ml.training.train_logistic_regression import run_logistic_regression_training
from services.digital_twin.ml.training.train_decision_tree import run_decision_tree_training
from services.digital_twin.ml.training.train_random_forest import run_random_forest_training
from services.digital_twin.ml.training.train_svm import run_svm_training
from services.digital_twin.ml.comparison.model_comparator import model_comparator

def run_day104_suite():
    print("=" * 80)
    print("       WEEK 15 - DAY 104: XGBOOST BASELINE & 5-MODEL AUDIT")
    print("=" * 80 + "\n")

    # 1. Hyperparameter Architecture Audit
    print("[1/7] Auditing XGBoost Classifier Architecture...")
    clf = AttackXGBoostClassifier(random_seed=42)
    assert clf.model_name == "xgboost"
    assert clf.hyperparameters["n_estimators"] == 100
    assert clf.hyperparameters["max_depth"] == 4
    assert clf.hyperparameters["learning_rate"] == 0.1
    assert clf.hyperparameters["subsample"] == 0.8
    assert clf.hyperparameters["colsample_bytree"] == 0.8
    assert clf.hyperparameters["objective"] == "binary:logistic"
    print("    [PASS] XGBoost initialized with regularization and subsampling parameters.")

    # 2. Training on Normalized Datasets
    print("\n[2/7] Loading Datasets and Executing Model Training...")
    X_train, y_train, X_test, y_test, features = dataset_loader.load_train_test()
    meta = clf.train(X_train, y_train, feature_names=features)

    assert clf.is_fitted is True
    assert meta.trainingRecordsCount == X_train.shape[0]
    print(f"    [PASS] XGBoost fitted on {meta.trainingRecordsCount} samples with {meta.featureCount} features.")

    # 3. Probability Calibration & Prediction Output
    print("\n[3/7] Auditing Gradient Boosting Probabilities & Predictions...")
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)

    assert preds.shape == (X_test.shape[0],)
    assert probs.shape == (X_test.shape[0], 2)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.allclose(probs.sum(axis=1), 1.0)
    print(f"    Sample XGBoost Probabilities: {probs[:3, 1]}")
    print("    [PASS] Continuous probabilities properly bounded and summing to 1.0.")

    # 4. Standard Metric Evaluation
    print("\n[4/7] Evaluating Classification Metrics...")
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
    print("    [PASS] Standard metrics evaluated successfully.")

    # 5. Feature Importances Audit
    print("\n[5/7] Auditing Gain-Based Feature Importances...")
    importances = clf.get_feature_importances(features)
    assert len(importances) == len(features)
    total_imp = sum(importances.values())
    print(f"    Total Feature Importance Sum: {total_imp:.4f}")
    assert abs(total_imp - 1.0) < 1e-3

    top_3 = list(importances.items())[:3]
    print(f"    Top 3 Informative Features : {top_3}")
    print("    [PASS] Feature importances validated across all 20 dimensions.")

    # 6. Artifact Generation & Storage Audit
    print("\n[6/7] Executing Automated Artifact Generation...")
    res = run_xgboost_training()
    art_dir = Path(res["artifactsPath"])

    assert (art_dir / "model.joblib").exists()
    assert (art_dir / "metadata.json").exists()
    assert (art_dir / "metrics.json").exists()

    with open(art_dir / "metrics.json", "r", encoding="utf-8") as f:
        stored_metrics = json.load(f)
    assert "standardEvaluation" in stored_metrics
    assert "rankedFeatureTable" in stored_metrics
    print(f"    [PASS] All artifacts successfully persisted to {art_dir}.")

    # 7. Complete 5-Model Comparative Evaluation Audit
    print("\n[7/7] Auditing Complete 5-Model Comparison Table (Days 100-104)...")
    run_logistic_regression_training()
    run_decision_tree_training()
    run_random_forest_training()
    run_svm_training()

    comp = model_comparator.generate_comparison()
    table = comp["comparisonTable"]
    print(f"    Total Baselines Compared: {comp['modelsCompared']}")
    print(f"    Top Baseline            : {comp['bestBaseline']}")
    print("\n    | Model                  | Accuracy | Precision | Recall | F1-Score | ROC-AUC |")
    print("    |------------------------|----------|-----------|--------|----------|---------|")
    for row in table:
        auc_str = f"{row['rocAuc']:.4f}" if row.get("rocAuc") is not None else "N/A"
        print(f"    | {row['model']:<22} | {row['accuracy']:<8.4f} | {row['precision']:<9.4f} | {row['recall']:<6.4f} | {row['f1Score']:<8.4f} | {auc_str:<7} |")

    assert len(table) == 5
    expected_models = {"Logistic Regression", "Decision Tree", "Random Forest", "Support Vector Machine", "XGBoost"}
    present_models = {r["model"] for r in table}
    assert expected_models.issubset(present_models)
    print("    [PASS] Complete 5-model comparative table validated without manual entry.")

    print("\n" + "=" * 80)
    print("       ALL DAY 104 XGBOOST & 5-MODEL TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day104_suite()