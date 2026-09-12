from typing import Dict, Any, Optional, List
import time
import numpy as np
from sklearn.svm import SVC
from sklearn.calibration import CalibratedClassifierCV
from services.digital_twin.ml.models.base_classifier import BaseAttackClassifier
from services.digital_twin.ml.training.experiment_models import ExperimentMetadata

class AttackSVMClassifier(BaseAttackClassifier):
    """Support Vector Machine baseline classifier with RBF kernel and probability calibration."""

    def __init__(
        self,
        random_seed: int = 42,
        hyperparameters: Optional[Dict[str, Any]] = None
    ):
        defaults = {
            "C": 1.0,
            "kernel": "rbf",
            "gamma": "scale",
            "class_weight": "balanced",
            "probability": True
        }
        if hyperparameters:
            defaults.update(hyperparameters)
        super().__init__(
            model_name="svm",
            random_seed=random_seed,
            hyperparameters=defaults
        )
        self.training_duration_ms: float = 0.0
        self.base_svc: Optional[SVC] = None

    def _build_model(self):
        self.base_svc = SVC(
            C=float(self.hyperparameters.get("C", 1.0)),
            kernel=str(self.hyperparameters.get("kernel", "rbf")),
            gamma=self.hyperparameters.get("gamma", "scale"),
            class_weight=self.hyperparameters.get("class_weight", "balanced"),
            random_state=self.random_seed
        )
        if self.hyperparameters.get("probability", True):
            self.model = CalibratedClassifierCV(estimator=self.base_svc, ensemble=False)
        else:
            self.model = self.base_svc

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]] = None) -> ExperimentMetadata:
        t0 = time.perf_counter()
        meta = super().train(X, y, feature_names=feature_names)
        self.training_duration_ms = round((time.perf_counter() - t0) * 1000, 3)

        svc_inst = self._get_underlying_svc()
        if self.metadata:
            self.metadata.hyperparameters["trainingDurationMs"] = self.training_duration_ms
            if svc_inst and hasattr(svc_inst, "n_support_"):
                self.metadata.hyperparameters["supportVectorCount"] = int(np.sum(svc_inst.n_support_))
                self.metadata.hyperparameters["supportVectorsPerClass"] = [int(v) for v in svc_inst.n_support_]

        return meta

    def _get_underlying_svc(self) -> Optional[SVC]:
        if isinstance(self.model, CalibratedClassifierCV):
            if hasattr(self.model, "calibrated_classifiers_") and self.model.calibrated_classifiers_:
                return self.model.calibrated_classifiers_[0].estimator
            return self.base_svc
        return self.model

    def get_decision_function(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model must be trained before calling decision_function()")
        svc_inst = self._get_underlying_svc()
        if svc_inst and hasattr(svc_inst, "decision_function"):
            return svc_inst.decision_function(X)
        probs = self.predict_proba(X)
        p1 = probs[:, 1]
        return np.log(np.clip(p1, 1e-6, 1 - 1e-6) / (1.0 - np.clip(p1, 1e-6, 1 - 1e-6)))

    def get_support_vector_stats(self) -> Dict[str, Any]:
        if not self.is_fitted:
            raise ValueError("Model must be trained before inspecting support vectors.")
        svc_inst = self._get_underlying_svc()
        if svc_inst and hasattr(svc_inst, "n_support_"):
            n_sup = [int(v) for v in svc_inst.n_support_]
            tot_sup = int(np.sum(svc_inst.n_support_))
        else:
            n_sup = []
            tot_sup = 0
        return {
            "totalSupportVectors": tot_sup,
            "supportVectorsPerClass": n_sup,
            "trainingDurationMs": self.training_duration_ms
        }

svm_classifier = AttackSVMClassifier()