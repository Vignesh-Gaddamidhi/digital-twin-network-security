import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.decision_tree.decision_tree_classifier import AttackDecisionTreeClassifier
from services.digital_twin.ml.training.train_decision_tree import run_decision_tree_training

def run_day101_suite():
    print("=" * 80)
    print("       WEEK 15 - DAY 101: DECISION TREE BASELINE AUDIT")
    print("=" * 80 + "\n")

    # 1. Parameter Architecture Audit
    print("[1/6] Auditing Decision Tree Parameter Architecture...")
    clf = AttackDecisionTreeClassifier(random_seed=42)
    assert clf.model_name == "decision_tree"
    assert clf.hyperparameters["criterion"] == "gini"
    assert clf.hyperparameters["max_depth"] == 6
    assert clf.hyperparameters["min_samples_split"] == 4
    assert clf.hyperparameters["min_samples_leaf"] == 2
    assert clf.hyperparameters["class_weight"] == "balanced"
    print("    [PASS] Decision Tree parameters correctly configured with depth controls.")

    # 2. Training on Normalized Datasets
    print("\n[2/6] Loading Datasets and Executing Model Training...")
    X_train, y_train, X_test, y_test, features = dataset_loader.load_train_test()
    meta = clf.train(X_train, y_train, feature_names=features)

    assert clf.is_fitted is True
    assert meta.trainingRecordsCount == X_train.shape[0]
    print(f"    [PASS] Trained on {meta.trainingRecordsCount} samples with {meta.featureCount} features.")

    # 3. Probability & Prediction Calibration
    print("\n[3/6] Auditing Prediction Output and Leaf Probability Estimates...")
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)

    assert preds.shape == (X_test.shape[0],)
    assert probs.shape == (X_test.shape[0], 2)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.allclose(probs.sum(axis=1), 1.0)
    print("    [PASS] Decision tree predictions and leaf probabilities properly formatted.")

    # 4. Standard Metric Evaluation
    print("\n[4/6] Evaluating Classification Metrics...")
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
    print("    [PASS] Metrics computed matching evaluation framework.")

    # 5. Feature Importances Audit
    print("\n[5/6] Auditing MDI Feature Importances...")
    importances = clf.get_feature_importances(features)
    assert len(importances) == len(features)

    total_imp = sum(importances.values())
    print(f"    Total Feature Importance Sum: {total_imp:.4f}")
    assert abs(total_imp - 1.0) < 1e-4

    top_3 = list(importances.items())[:3]
    print(f"    Top 3 Informative Features : {top_3}")
    print("    [PASS] Feature importances sum to 1.0 and rank feature dimensions.")

    # 6. Artifact Generation & Storage Audit
    print("\n[6/6] Executing Automated Artifact Generation...")
    res = run_decision_tree_training()
    art_dir = Path(res["artifactsPath"])

    assert (art_dir / "model.joblib").exists()
    assert (art_dir / "metadata.json").exists()
    assert (art_dir / "metrics.json").exists()

    with open(art_dir / "metrics.json", "r", encoding="utf-8") as f:
        stored_metrics = json.load(f)
    assert "standardEvaluation" in stored_metrics
    assert "featureImportances" in stored_metrics
    print(f"    [PASS] All artifacts successfully persisted to {art_dir}.")

    print("\n" + "=" * 80)
    print("       ALL DAY 101 DECISION TREE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day101_suite()