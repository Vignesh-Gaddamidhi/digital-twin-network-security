from typing import Dict, Any, Optional
from sklearn.linear_model import LogisticRegression
from services.digital_twin.ml.models.base_classifier import BaseAttackClassifier

class AttackLogisticRegressionClassifier(BaseAttackClassifier):
    """Logistic Regression baseline classifier for binary network attack detection."""

    def __init__(
        self,
        random_seed: int = 42,
        hyperparameters: Optional[Dict[str, Any]] = None
    ):
        defaults = {
            "solver": "lbfgs",
            "C": 1.0,
            "max_iter": 500,
            "class_weight": "balanced"
        }
        if hyperparameters:
            defaults.update(hyperparameters)
        super().__init__(
            model_name="logistic_regression",
            random_seed=random_seed,
            hyperparameters=defaults
        )

    def _build_model(self):
        self.model = LogisticRegression(
            solver=self.hyperparameters.get("solver", "lbfgs"),
            C=float(self.hyperparameters.get("C", 1.0)),
            max_iter=int(self.hyperparameters.get("max_iter", 500)),
            class_weight=self.hyperparameters.get("class_weight", "balanced"),
            random_state=self.random_seed
        )

logistic_regression_classifier = AttackLogisticRegressionClassifier()