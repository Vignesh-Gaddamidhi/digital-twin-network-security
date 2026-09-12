import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.svm.svm_classifier import AttackSVMClassifier
from services.digital_twin.ml.training.train_svm import run_svm_training
from services.digital_twin.ml.training.train_logistic_regression import run_logistic_regression_training
from services.digital_twin.ml.training.train_decision_tree import run_decision_tree_training
from services.digital_twin.ml.training.train_random_forest import run_random_forest_training
from services.digital_twin.ml.comparison.model_comparator import model_comparator

def run_day103_suite():
    print("=" * 80)
    print("       WEEK 15 - DAY 103: SUPPORT VECTOR MACHINE BASELINE AUDIT")
    print("=" * 80 + "\n")

    # 1. Parameter Architecture Audit
    print("[1/7] Auditing SVM Classifier Architecture...")
    clf = AttackSVMClassifier(random_seed=42)
    assert clf.model_name == "svm"
    assert clf.hyperparameters["C"] == 1.0
    assert clf.hyperparameters["kernel"] == "rbf"
    assert clf.hyperparameters["gamma"] == "scale"
    assert clf.hyperparameters["class_weight"] == "balanced"
    assert clf.hyperparameters["probability"] is True
    print("    [PASS] SVM initialized with RBF kernel and calibrated probability configuration.")

    # 2. Training on Normalized Datasets
    print("\n[2/7] Loading Datasets and Executing Model Training...")
    X_train, y_train, X_test, y_test, features = dataset_loader.load_train_test()
    meta = clf.train(X_train, y_train, feature_names=features)

    assert clf.is_fitted is True
    assert meta.trainingRecordsCount == X_train.shape[0]
    print(f"    [PASS] SVM trained on {meta.trainingRecordsCount} samples with {meta.featureCount} features.")

    # 3. Decision Function & Continuous Probabilities
    print("\n[3/7] Auditing Signed Decision Distances & Continuous Probabilities...")
    dec_scores = clf.get_decision_function(X_test)
    probs = clf.predict_proba(X_test)
    preds = clf.predict(X_test)

    assert dec_scores.shape == (X_test.shape[0],)
    assert probs.shape == (X_test.shape[0], 2)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.allclose(probs.sum(axis=1), 1.0)
    print(f"    Sample Decision Distance Scores : {dec_scores[:3]}")
    print(f"    Sample Calibrated Probabilities  : {probs[:3, 1]}")
    print("    [PASS] Both raw decision distances and Platt-scaled probabilities verified.")

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
    print("    [PASS] Metrics computed matching evaluation framework.")

    # 5. Support Vector Analysis & Latency Metrics
    print("\n[5/7] Auditing Support Vector Counts & Training Duration...")
    sv_stats = clf.get_support_vector_stats()
    print(f"    Total Support Vectors      : {sv_stats['totalSupportVectors']}")
    print(f"    Support Vectors per Class  : {sv_stats['supportVectorsPerClass']}")
    print(f"    Training Duration          : {sv_stats['trainingDurationMs']} ms")

    assert sv_stats["totalSupportVectors"] > 0
    assert sv_stats["trainingDurationMs"] >= 0.0
    print("    [PASS] Support vector geometry verified.")

    # 6. Artifact Generation & Storage Audit
    print("\n[6/7] Executing Automated Artifact Generation...")
    res = run_svm_training()
    art_dir = Path(res["artifactsPath"])

    assert (art_dir / "model.joblib").exists()
    assert (art_dir / "metadata.json").exists()
    assert (art_dir / "metrics.json").exists()

    with open(art_dir / "metrics.json", "r", encoding="utf-8") as f:
        stored_metrics = json.load(f)
    assert "standardEvaluation" in stored_metrics
    assert "supportVectorStats" in stored_metrics
    print(f"    [PASS] All artifacts successfully persisted to {art_dir}.")

    # 7. 4-Model Comparative Evaluation Audit
    print("\n[7/7] Auditing Automated Multi-Model Comparison Table (Days 100, 101, 102, 103)...")
    run_logistic_regression_training()
    run_decision_tree_training()
    run_random_forest_training()

    comp = model_comparator.generate_comparison()
    table = comp["comparisonTable"]
    print(f"    Total Baselines Compared: {comp['modelsCompared']}")
    print(f"    Top Baseline            : {comp['bestBaseline']}")
    print("\n    | Model                  | Accuracy | Precision | Recall | F1-Score | ROC-AUC |")
    print("    |------------------------|----------|-----------|--------|----------|---------|")
    for row in table:
        auc_str = f"{row['rocAuc']:.4f}" if row.get("rocAuc") is not None else "N/A"
        print(f"    | {row['model']:<22} | {row['accuracy']:<8.4f} | {row['precision']:<9.4f} | {row['recall']:<6.4f} | {row['f1Score']:<8.4f} | {auc_str:<7} |")

    assert len(table) == 4
    assert any(r["model"] == "Support Vector Machine" for r in table)
    print("    [PASS] 4-Model automated comparison table verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 103 SVM TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day103_suite()