import json
from pathlib import Path
from typing import Dict, Any, List
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "logistic_regression"

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.logistic_regression.logistic_regression_classifier import AttackLogisticRegressionClassifier

def evaluate_custom_threshold(probs: np.ndarray, y_true: np.ndarray, threshold: float = 0.50) -> Dict[str, Any]:
    pos_probs = probs[:, 1] if probs.ndim == 2 else probs
    preds = (pos_probs >= threshold).astype(int)

    tp = int(np.sum((preds == 1) & (y_true == 1)))
    fp = int(np.sum((preds == 1) & (y_true == 0)))
    tn = int(np.sum((preds == 0) & (y_true == 0)))
    fn = int(np.sum((preds == 0) & (y_true == 1)))

    acc = (tp + tn) / max(1, (tp + tn + fp + fn))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = (2 * prec * rec) / max(1e-6, (prec + rec))

    return {
        "threshold": threshold,
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "confusionMatrix": [[tn, fp], [fn, tp]],
        "tp": tp, "fp": fp, "tn": tn, "fn": fn
    }

def run_logistic_regression_training() -> Dict[str, Any]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    X_train, y_train, X_test, y_test, feature_names = dataset_loader.load_train_test()

    clf = AttackLogisticRegressionClassifier(random_seed=42)
    meta = clf.train(X_train, y_train, feature_names=feature_names)
    default_metrics = clf.evaluate(X_test, y_test)

    test_probs = clf.predict_proba(X_test)
    threshold_050 = evaluate_custom_threshold(test_probs, y_test, threshold=0.50)
    threshold_035 = evaluate_custom_threshold(test_probs, y_test, threshold=0.35)

    model_path = ARTIFACTS_DIR / "model.joblib"
    clf.save(model_path)

    metadata_dict = {
        "experimentId": meta.experimentId,
        "modelName": "logistic_regression",
        "datasetVersion": meta.datasetVersion,
        "featureVersion": meta.featureVersion,
        "trainingSamples": int(X_train.shape[0]),
        "testingSamples": int(X_test.shape[0]),
        "featureCount": len(feature_names),
        "hyperparameters": clf.hyperparameters,
        "randomSeed": clf.random_seed
    }
    with open(ARTIFACTS_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)

    metrics_dict = {
        "standardEvaluation": default_metrics.model_dump(),
        "thresholdAnalysis": {
            "threshold_0_50": threshold_050,
            "threshold_0_35": threshold_035
        }
    }
    with open(ARTIFACTS_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_dict, f, indent=2)

    return {
        "metadata": metadata_dict,
        "metrics": metrics_dict,
        "artifactsPath": str(ARTIFACTS_DIR)
    }

if __name__ == "__main__":
    result = run_logistic_regression_training()
    print("Logistic Regression Training & Evaluation Finished.")
    print(json.dumps(result["metrics"], indent=2))