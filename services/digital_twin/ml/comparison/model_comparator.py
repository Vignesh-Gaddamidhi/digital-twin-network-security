import json
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parents[4]
ARTIFACTS_ROOT = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts"

class ModelComparator:
    """Aggregates and compares evaluation metrics across all Week 15 trained models."""

    MODEL_DIRS = {
        "Logistic Regression": ARTIFACTS_ROOT / "logistic_regression",
        "Decision Tree": ARTIFACTS_ROOT / "decision_tree",
        "Random Forest": ARTIFACTS_ROOT / "random_forest"
    }

    def generate_comparison(self) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []

        for model_label, model_dir in self.MODEL_DIRS.items():
            metrics_file = model_dir / "metrics.json"
            if metrics_file.exists():
                try:
                    with open(metrics_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    eval_metrics = data.get("standardEvaluation", {})
                    rows.append({
                        "model": model_label,
                        "accuracy": eval_metrics.get("accuracy", 0.0),
                        "precision": eval_metrics.get("precision", 0.0),
                        "recall": eval_metrics.get("recall", 0.0),
                        "f1Score": eval_metrics.get("f1Score", 0.0),
                        "rocAuc": eval_metrics.get("rocAuc", 0.0),
                        "truePositives": eval_metrics.get("truePositives", 0),
                        "falsePositives": eval_metrics.get("falsePositives", 0),
                        "trueNegatives": eval_metrics.get("trueNegatives", 0),
                        "falseNegatives": eval_metrics.get("falseNegatives", 0)
                    })
                except Exception:
                    pass

        # Sort leaderboard by F1-Score descending, then ROC-AUC
        sorted_rows = sorted(rows, key=lambda r: (r["f1Score"], r.get("rocAuc") or 0.0), reverse=True)

        return {
            "comparisonTable": sorted_rows,
            "modelsCompared": len(sorted_rows),
            "bestBaseline": sorted_rows[0]["model"] if sorted_rows else "NONE"
        }

model_comparator = ModelComparator()