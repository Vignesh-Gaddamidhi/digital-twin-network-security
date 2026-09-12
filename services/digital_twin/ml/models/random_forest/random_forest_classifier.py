from typing import Dict, Any, Optional, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from services.digital_twin.ml.models.base_classifier import BaseAttackClassifier

class AttackRandomForestClassifier(BaseAttackClassifier):
    """Random Forest ensemble classifier for binary network intrusion detection."""

    def __init__(
        self,
        random_seed: int = 42,
        hyperparameters: Optional[Dict[str, Any]] = None
    ):
        defaults = {
            "n_estimators": 100,
            "max_depth": 8,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "max_features": "sqrt",
            "class_weight": "balanced",
            "oob_score": True
        }
        if hyperparameters:
            defaults.update(hyperparameters)
        super().__init__(
            model_name="random_forest",
            random_seed=random_seed,
            hyperparameters=defaults
        )

    def _build_model(self):
        self.model = RandomForestClassifier(
            n_estimators=int(self.hyperparameters.get("n_estimators", 100)),
            max_depth=int(self.hyperparameters.get("max_depth", 8)),
            min_samples_split=int(self.hyperparameters.get("min_samples_split", 4)),
            min_samples_leaf=int(self.hyperparameters.get("min_samples_leaf", 2)),
            max_features=self.hyperparameters.get("max_features", "sqrt"),
            class_weight=self.hyperparameters.get("class_weight", "balanced"),
            oob_score=bool(self.hyperparameters.get("oob_score", True)),
            random_state=self.random_seed,
            n_jobs=-1
        )

    def get_feature_importances(self, feature_names: Optional[List[str]] = None) -> Dict[str, float]:
        if not self.is_fitted or self.model is None:
            raise ValueError("Model must be trained before extracting feature importances.")

        raw_importances = self.model.feature_importances_
        names = feature_names or (self.metadata.featureNames if self.metadata else [f"f_{i}" for i in range(len(raw_importances))])

        importance_dict = {
            name: round(float(imp), 6)
            for name, imp in zip(names, raw_importances)
        }
        return dict(sorted(importance_dict.items(), key=lambda item: item[1], reverse=True))

    def get_oob_score(self) -> Optional[float]:
        if self.is_fitted and hasattr(self.model, "oob_score_"):
            return round(float(self.model.oob_score_), 4)
        return None

random_forest_classifier = AttackRandomForestClassifier()