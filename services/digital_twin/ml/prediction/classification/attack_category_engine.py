import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "multiclass"

from services.digital_twin.ml.prediction.classification.classification_models import (
    CanonicalAttackCategory, MultiClassPredictionOutput, CLASS_TO_INT, INT_TO_CLASS
)
from services.digital_twin.ml.prediction.classification.multiclass_dataset_adapter import multiclass_dataset_adapter
from services.digital_twin.ml.models.multiclass.multiclass_models import (
    MultiClassRandomForest, MultiClassXGBoost, MultiClassLogisticRegression
)

class AttackCategoryClassificationEngine:
    """Coordinates training, prediction, and confidence scoring across 8 threat classes."""

    def __init__(self, artifacts_dir: Path = ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.active_model = None
        self.active_model_name = "multiclass_random_forest"
        self.fitted_classes: List[str] = list(CLASS_TO_INT.keys())

    def train_baseline_model(self, model_type: str = "random_forest") -> Dict[str, Any]:
        X_tr, y_tr, X_te, y_te, feats, dist = multiclass_dataset_adapter.load_multiclass_data()

        if model_type.lower() in ("xgboost", "xgb"):
            self.active_model = MultiClassXGBoost(random_seed=42, num_classes=len(CLASS_TO_INT))
            self.active_model_name = "multiclass_xgboost"
        elif model_type.lower() in ("logistic_regression", "lr"):
            self.active_model = MultiClassLogisticRegression(random_seed=42)
            self.active_model_name = "multiclass_logistic_regression"
        else:
            self.active_model = MultiClassRandomForest(random_seed=42)
            self.active_model_name = "multiclass_random_forest"

        self.active_model.fit(X_tr, y_tr)

        # Evaluate on test partition
        test_preds = self.active_model.predict(X_te)
        test_acc = float(np.mean(test_preds == y_te))

        # Persist artifact
        out_path = self.artifacts_dir / f"{self.active_model_name}.joblib"
        joblib.dump(self.active_model, out_path)

        meta = {
            "modelName": self.active_model_name,
            "trainingSamples": int(X_tr.shape[0]),
            "testSamples": int(X_te.shape[0]),
            "featureCount": len(feats),
            "classes": self.fitted_classes,
            "trainingDistribution": dist,
            "testAccuracy": round(test_acc, 4),
            "artifactPath": str(out_path)
        }

        with open(self.artifacts_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return meta

    def classify_behavior(
        self,
        features: np.ndarray,
        model_name: Optional[str] = None
    ) -> MultiClassPredictionOutput:
        if self.active_model is None:
            self.train_baseline_model("random_forest")

        if features.ndim == 1:
            features = features.reshape(1, -1)

        probs = self.active_model.predict_proba(features)[0]

        # Build full 8-class distribution dictionary
        distribution: Dict[str, float] = {}
        for idx, cat_name in enumerate(self.fitted_classes):
            prob_val = float(probs[idx]) if idx < len(probs) else 0.0
            distribution[cat_name] = round(prob_val, 4)

        # Identify top predicted category and its confidence
        top_cat_name = max(distribution, key=distribution.get)
        top_conf = distribution[top_cat_name]

        output = MultiClassPredictionOutput(
            predictedCategory=CanonicalAttackCategory(top_cat_name),
            categoryConfidence=top_conf,
            categoryConfidenceFormatted=f"{round(top_conf * 100, 1)}%",
            classDistribution=distribution,
            modelName=model_name or self.active_model_name
        )
        return output

attack_category_engine = AttackCategoryClassificationEngine()