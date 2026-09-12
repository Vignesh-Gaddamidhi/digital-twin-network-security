from typing import Dict, Any, Optional, List
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from services.digital_twin.ml.models.base_classifier import BaseAttackClassifier

class AttackDecisionTreeClassifier(BaseAttackClassifier):
    """Decision Tree baseline classifier for binary network attack classification."""

    def __init__(
        self,
        random_seed: int = 42,
        hyperparameters: Optional[Dict[str, Any]] = None
    ):
        defaults = {
            "criterion": "gini",
            "max_depth": 6,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "class_weight": "balanced"
        }
        if hyperparameters:
            defaults.update(hyperparameters)
        super().__init__(
            model_name="decision_tree",
            random_seed=random_seed,
            hyperparameters=defaults
        )

    def _build_model(self):
        self.model = DecisionTreeClassifier(
            criterion=self.hyperparameters.get("criterion", "gini"),
            max_depth=self.hyperparameters.get("max_depth", 6),
            min_samples_split=self.hyperparameters.get("min_samples_split", 4),
            min_samples_leaf=self.hyperparameters.get("min_samples_leaf", 2),
            class_weight=self.hyperparameters.get("class_weight", "balanced"),
            random_state=self.random_seed
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
        # Sort descending by importance
        return dict(sorted(importance_dict.items(), key=lambda item: item[1], reverse=True))

decision_tree_classifier = AttackDecisionTreeClassifier()