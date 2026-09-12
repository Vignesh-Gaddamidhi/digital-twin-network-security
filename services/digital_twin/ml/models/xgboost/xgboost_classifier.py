from typing import Dict, Any, Optional, List
import numpy as np
from xgboost import XGBClassifier
from services.digital_twin.ml.models.base_classifier import BaseAttackClassifier

class AttackXGBoostClassifier(BaseAttackClassifier):
    """XGBoost gradient boosting classifier for binary network attack detection."""

    def __init__(
        self,
        random_seed: int = 42,
        hyperparameters: Optional[Dict[str, Any]] = None
    ):
        defaults = {
            "n_estimators": 100,
            "max_depth": 4,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "objective": "binary:logistic",
            "eval_metric": "logloss"
        }
        if hyperparameters:
            defaults.update(hyperparameters)
        super().__init__(
            model_name="xgboost",
            random_seed=random_seed,
            hyperparameters=defaults
        )

    def _build_model(self):
        self.model = XGBClassifier(
            n_estimators=int(self.hyperparameters.get("n_estimators", 100)),
            max_depth=int(self.hyperparameters.get("max_depth", 4)),
            learning_rate=float(self.hyperparameters.get("learning_rate", 0.1)),
            subsample=float(self.hyperparameters.get("subsample", 0.8)),
            colsample_bytree=float(self.hyperparameters.get("colsample_bytree", 0.8)),
            objective=str(self.hyperparameters.get("objective", "binary:logistic")),
            eval_metric=str(self.hyperparameters.get("eval_metric", "logloss")),
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

xgboost_classifier = AttackXGBoostClassifier()