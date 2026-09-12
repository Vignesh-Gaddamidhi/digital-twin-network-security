from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import numpy as np
import joblib

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from services.digital_twin.ml.training.experiment_models import ExperimentMetadata, ModelEvaluationMetrics

ROOT_DIR = Path(__file__).resolve().parents[4]
ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts"

class BaseAttackClassifier(ABC):
    """Abstract interface defining the standardized contract for all Phase 12 ML classifiers."""

    def __init__(self, model_name: str, random_seed: int = 42, hyperparameters: Optional[Dict[str, Any]] = None):
        self.model_name = model_name
        self.random_seed = random_seed
        self.hyperparameters = hyperparameters or {}
        self.model = None
        self.metadata: Optional[ExperimentMetadata] = None
        self.is_fitted: bool = False

    @abstractmethod
    def _build_model(self):
        """Instantiates the underlying scikit-learn or XGBoost model instance."""
        pass

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]] = None) -> ExperimentMetadata:
        self._build_model()
        self.model.fit(X, y)
        self.is_fitted = True

        self.metadata = ExperimentMetadata(
            modelName=self.model_name,
            hyperparameters=self.hyperparameters,
            randomSeed=self.random_seed,
            trainingRecordsCount=int(X.shape[0]),
            featureCount=int(X.shape[1]),
            featureNames=feature_names or [f"f_{i}" for i in range(X.shape[1])]
        )
        return self.metadata

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted or self.model is None:
            raise ValueError(f"Model '{self.model_name}' must be trained before calling predict()")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted or self.model is None:
            raise ValueError(f"Model '{self.model_name}' must be trained before calling predict_proba()")
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        elif hasattr(self.model, "decision_function"):
            # Normalize decision function to [0, 1] probability range
            df = self.model.decision_function(X)
            prob_1 = 1.0 / (1.0 + np.exp(-df))
            prob_0 = 1.0 - prob_1
            return np.column_stack([prob_0, prob_1])
        else:
            preds = self.predict(X)
            return np.column_stack([1.0 - preds, preds])

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> ModelEvaluationMetrics:
        preds = self.predict(X)
        probs = self.predict_proba(X)
        prob_positive = probs[:, 1] if probs.ndim == 2 and probs.shape[1] > 1 else probs

        acc = float(accuracy_score(y, preds))
        prec = float(precision_score(y, preds, zero_division=0))
        rec = float(recall_score(y, preds, zero_division=0))
        f1 = float(f1_score(y, preds, zero_division=0))

        roc_auc = None
        try:
            if len(np.unique(y)) > 1:
                roc_auc = float(roc_auc_score(y, prob_positive))
        except Exception:
            roc_auc = None

        cm = confusion_matrix(y, preds).tolist()
        tn = int(cm[0][0]) if len(cm) > 0 and len(cm[0]) > 0 else 0
        fp = int(cm[0][1]) if len(cm) > 0 and len(cm[0]) > 1 else 0
        fn = int(cm[1][0]) if len(cm) > 1 and len(cm[1]) > 0 else 0
        tp = int(cm[1][1]) if len(cm) > 1 and len(cm[1]) > 1 else 0

        metrics = ModelEvaluationMetrics(
            accuracy=round(acc, 4),
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1Score=round(f1, 4),
            rocAuc=round(roc_auc, 4) if roc_auc is not None else None,
            confusionMatrix=cm,
            truePositives=tp,
            falsePositives=fp,
            trueNegatives=tn,
            falseNegatives=fn
        )

        if self.metadata:
            self.metadata.testingRecordsCount = int(X.shape[0])
            self.metadata.metrics = metrics

        return metrics

    def save(self, filepath: Optional[Path] = None) -> Path:
        if not self.is_fitted or self.model is None:
            raise ValueError(f"Cannot save unfitted model '{self.model_name}'")
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = filepath or (ARTIFACTS_DIR / f"{self.model_name.lower()}_v1.joblib")
        joblib.dump({"model": self.model, "metadata": self.metadata.model_dump() if self.metadata else {}}, out_path)
        if self.metadata:
            self.metadata.artifactPath = str(out_path)
        return out_path

    def load(self, filepath: Path):
        data = joblib.load(filepath)
        self.model = data["model"]
        if "metadata" in data and data["metadata"]:
            self.metadata = ExperimentMetadata(**data["metadata"])
        self.is_fitted = True