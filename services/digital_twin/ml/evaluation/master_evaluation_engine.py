import json
import csv
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT_DIR = Path(__file__).resolve().parents[4]
ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts"
COMPARISON_DIR = ARTIFACTS_DIR / "comparison"
CM_IMAGES_DIR = COMPARISON_DIR / "confusion_matrices"

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.logistic_regression.logistic_regression_classifier import AttackLogisticRegressionClassifier
from services.digital_twin.ml.models.decision_tree.decision_tree_classifier import AttackDecisionTreeClassifier
from services.digital_twin.ml.models.random_forest.random_forest_classifier import AttackRandomForestClassifier
from services.digital_twin.ml.models.svm.svm_classifier import AttackSVMClassifier
from services.digital_twin.ml.models.xgboost.xgboost_classifier import AttackXGBoostClassifier

class MasterEvaluationEngine:
    """Orchestrates comprehensive cross-model evaluation, metrics aggregation, and visualization."""

    def __init__(self):
        COMPARISON_DIR.mkdir(parents=True, exist_ok=True)
        CM_IMAGES_DIR.mkdir(parents=True, exist_ok=True)

    def _render_confusion_matrix_png(self, model_key: str, model_name: str, cm: List[List[int]]) -> str:
        plt.figure(figsize=(5, 4))
        cm_arr = np.array(cm)
        plt.imshow(cm_arr, interpolation="nearest", cmap=plt.cm.Blues)
        plt.title(f"Confusion Matrix: {model_name}")
        plt.colorbar()

        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ["Normal (0)", "Anomaly (1)"])
        plt.yticks(tick_marks, ["Normal (0)", "Anomaly (1)"])

        thresh = cm_arr.max() / 2.0 if cm_arr.max() > 0 else 1.0
        for i in range(cm_arr.shape[0]):
            for j in range(cm_arr.shape[1]):
                plt.text(j, i, format(cm_arr[i, j], "d"),
                         ha="center", va="center",
                         color="white" if cm_arr[i, j] > thresh else "black")

        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.tight_layout()

        out_path = CM_IMAGES_DIR / f"{model_key}.png"
        plt.savefig(out_path, dpi=120)
        plt.close()
        return str(out_path)

    def run_master_evaluation(self) -> Dict[str, Any]:
        X_train, y_train, X_test, y_test, feature_names = dataset_loader.load_train_test()

        model_registry = [
            ("logistic_regression", "Logistic Regression", AttackLogisticRegressionClassifier(random_seed=42)),
            ("decision_tree", "Decision Tree", AttackDecisionTreeClassifier(random_seed=42)),
            ("random_forest", "Random Forest", AttackRandomForestClassifier(random_seed=42)),
            ("svm", "Support Vector Machine", AttackSVMClassifier(random_seed=42)),
            ("xgboost", "XGBoost", AttackXGBoostClassifier(random_seed=42))
        ]

        results = []
        for key, name, clf in model_registry:
            # Measure training duration
            t0_train = time.perf_counter()
            clf.train(X_train, y_train, feature_names=feature_names)
            train_time_ms = round((time.perf_counter() - t0_train) * 1000, 3)

            # Measure inference duration
            t0_test = time.perf_counter()
            metrics = clf.evaluate(X_test, y_test)
            test_time_ms = round((time.perf_counter() - t0_test) * 1000, 3)

            # Save individual model artifacts
            model_dir = ARTIFACTS_DIR / key
            model_dir.mkdir(parents=True, exist_ok=True)
            clf.save(model_dir / "model.joblib")

            # Save individual metrics
            with open(model_dir / "metrics.json", "w", encoding="utf-8") as f:
                json.dump({"standardEvaluation": metrics.model_dump()}, f, indent=2)

            # Render Confusion Matrix PNG
            cm_png = self._render_confusion_matrix_png(key, name, metrics.confusionMatrix)

            # Cyber Risk Multi-Factor Selection Score
            roc_score = metrics.rocAuc if metrics.rocAuc is not None else 0.5
            cyber_score = round(
                0.35 * metrics.recall +
                0.30 * metrics.f1Score +
                0.15 * roc_score +
                0.10 * metrics.precision +
                0.10 * metrics.accuracy,
                4
            )

            results.append({
                "modelKey": key,
                "modelName": name,
                "accuracy": metrics.accuracy,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1Score": metrics.f1Score,
                "rocAuc": metrics.rocAuc,
                "confusionMatrix": metrics.confusionMatrix,
                "truePositives": metrics.truePositives,
                "falsePositives": metrics.falsePositives,
                "trueNegatives": metrics.trueNegatives,
                "falseNegatives": metrics.falseNegatives,
                "trainTimeMs": train_time_ms,
                "inferenceTimeMs": test_time_ms,
                "cyberScore": cyber_score,
                "confusionMatrixPng": cm_png
            })

        # Rank models by cyberScore descending, then F1-score
        ranked_results = sorted(results, key=lambda x: (x["cyberScore"], x["f1Score"]), reverse=True)
        for rank_idx, r in enumerate(ranked_results):
            r["rank"] = rank_idx + 1

        best_baseline = ranked_results[0]["modelName"]

        # Persist CSV
        csv_path = COMPARISON_DIR / "model_comparison.csv"
        fieldnames = ["rank", "modelName", "accuracy", "precision", "recall", "f1Score", "rocAuc", "falsePositives", "falseNegatives", "trainTimeMs", "inferenceTimeMs", "cyberScore"]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in ranked_results:
                writer.writerow(row)

        # Persist JSON report
        report_data = {
            "evaluationTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "datasetVersion": "dataset-v1.0",
            "trainSamples": int(X_train.shape[0]),
            "testSamples": int(X_test.shape[0]),
            "featureCount": len(feature_names),
            "features": feature_names,
            "bestBaseline": best_baseline,
            "modelsEvaluated": len(ranked_results),
            "leaderboard": ranked_results,
            "operationalRecommendations": {
                "highestRecall": max(ranked_results, key=lambda x: x["recall"])["modelName"],
                "lowestFalseAlerts": min(ranked_results, key=lambda x: x["falsePositives"])["modelName"],
                "fastestInference": min(ranked_results, key=lambda x: x["inferenceTimeMs"])["modelName"]
            }
        }

        with open(COMPARISON_DIR / "model_comparison.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        with open(COMPARISON_DIR / "report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return report_data

    def test_reproducibility(self) -> bool:
        """Executes dual sequential runs under identical seeds and asserts bitwise metric parity."""
        rep1 = self.run_master_evaluation()
        rep2 = self.run_master_evaluation()

        for m1, m2 in zip(rep1["leaderboard"], rep2["leaderboard"]):
            if m1["modelKey"] != m2["modelKey"]:
                return False
            if m1["accuracy"] != m2["accuracy"] or m1["f1Score"] != m2["f1Score"]:
                return False
            if m1["confusionMatrix"] != m2["confusionMatrix"]:
                return False
        return True

master_evaluation_engine = MasterEvaluationEngine()