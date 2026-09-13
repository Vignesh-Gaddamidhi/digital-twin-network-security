from typing import Dict, Any, Optional, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

class MultiClassRandomForest:
    def __init__(self, random_seed: int = 42, n_estimators: int = 100):
        self.random_seed = random_seed
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=10,
            class_weight="balanced",
            random_state=random_seed,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.is_fitted = True

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

class MultiClassXGBoost:
    def __init__(self, random_seed: int = 42, n_estimators: int = 100, num_classes: int = 8):
        self.random_seed = random_seed
        self.num_classes = num_classes
        self.model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=6,
            learning_rate=0.2,
            objective="multi:softprob",
            num_class=num_classes,
            eval_metric="mlogloss",
            random_state=random_seed,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.is_fitted = True

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

class MultiClassLogisticRegression:
    def __init__(self, random_seed: int = 42):
        self.random_seed = random_seed
        self.model = LogisticRegression(
            solver="lbfgs",
            max_iter=1000,
            class_weight="balanced",
            random_state=random_seed
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.is_fitted = True

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)