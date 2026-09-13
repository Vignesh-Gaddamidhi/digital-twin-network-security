import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import shap

ROOT_DIR = Path(__file__).resolve().parents[5]
XAI_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai"
SHAP_FILE = XAI_ARTIFACTS_DIR / "shap_explanations.json"

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES, dataset_loader
from services.digital_twin.ml.xai.shap.shap_models import (
    ContributionDirection, FeatureSHAPItem, SHAPExplanation
)

class SHAPExplainerEngine:
    """Computes exact and model-appropriate SHAP local explanations for network threat predictions."""

    def __init__(self, artifacts_dir: Path = XAI_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.explainers: Dict[str, Any] = {}
        self.history: List[SHAPExplanation] = []
        self._background_data: Optional[np.ndarray] = None

    def get_or_create_explainer(
        self,
        model: Any,
        model_name: str,
        background_data: Optional[np.ndarray] = None
    ) -> Any:
        m_key = model_name.lower()
        if m_key in self.explainers:
            return self.explainers[m_key]

        if background_data is None:
            if self._background_data is None:
                X_tr, _, _, _, _ = dataset_loader.load_train_test()
                # Use representative 50-sample background summary
                self._background_data = X_tr[:50]
            background_data = self._background_data

        # 1. Tree Models: TreeExplainer
        if hasattr(model, "feature_importances_") or "random_forest" in m_key or "tree" in m_key or "xgboost" in m_key:
            explainer = shap.TreeExplainer(model)
        # 2. Linear Models: LinearExplainer
        elif hasattr(model, "coef_") or "logistic" in m_key:
            explainer = shap.LinearExplainer(model, background_data)
        # 3. Fallback: Unified Explainer
        else:
            explainer = shap.Explainer(model.predict_proba if hasattr(model, "predict_proba") else model.predict, background_data)

        self.explainers[m_key] = explainer
        return explainer

    def explain_instance(
        self,
        prediction_id: str,
        features: Dict[str, float],
        model: Any,
        model_name: str = "random_forest",
        model_version: str = "1.0.0",
        feature_names: Optional[List[str]] = None
    ) -> SHAPExplanation:
        feat_names = feature_names or FEATURE_NAMES
        feat_vector = np.array([[float(features.get(fn, 0.0)) for fn in feat_names]], dtype=np.float32)

        explainer = self.get_or_create_explainer(model, model_name)
        raw_shap = explainer(feat_vector)

        # 1. Extract Base Value E[f(x)]
        if hasattr(raw_shap, "base_values"):
            bv = raw_shap.base_values
            if isinstance(bv, np.ndarray):
                # If binary classification outputs [base_class0, base_class1], pick positive class (index 1)
                base_val = float(bv[0, 1]) if bv.ndim == 2 and bv.shape[1] > 1 else float(bv.flatten()[0])
            else:
                base_val = float(bv)
        else:
            base_val = 0.50

        # 2. Extract Values Array
        if hasattr(raw_shap, "values"):
            vals = raw_shap.values
            if isinstance(vals, list):
                # Binary classification list of arrays [class_0, class_1]
                phi = vals[1][0] if len(vals) > 1 else vals[0][0]
            elif isinstance(vals, np.ndarray):
                if vals.ndim == 3 and vals.shape[2] > 1:
                    phi = vals[0, :, 1]  # Shape: (1, n_features, 2) -> select positive class
                elif vals.ndim == 2:
                    phi = vals[0]
                else:
                    phi = vals.flatten()
        else:
            phi = np.zeros(len(feat_names), dtype=np.float32)

        # 3. Model Prediction Value
        if hasattr(model, "predict_proba"):
            p_out = model.predict_proba(feat_vector)
            pred_val = float(p_out[0, 1]) if p_out.ndim == 2 and p_out.shape[1] > 1 else float(p_out.flatten()[0])
        elif hasattr(model, "predict"):
            pred_val = float(model.predict(feat_vector)[0])
        else:
            pred_val = float(base_val + np.sum(phi))

        # 4. Construct Feature Items
        items: List[FeatureSHAPItem] = []
        for idx, fn in enumerate(feat_names):
            phi_val = float(phi[idx]) if idx < len(phi) else 0.0
            obs_val = float(features.get(fn, 0.0))

            if phi_val > 1e-4:
                direction = ContributionDirection.POSITIVE
            elif phi_val < -1e-4:
                direction = ContributionDirection.NEGATIVE
            else:
                direction = ContributionDirection.NEUTRAL

            items.append(FeatureSHAPItem(
                featureName=fn,
                featureValue=round(obs_val, 4),
                shapValue=round(phi_val, 4),
                shapValueFormatted=f"{'+' if phi_val >= 0 else ''}{phi_val:.4f}",
                direction=direction,
                absoluteContribution=round(abs(phi_val), 4),
                rank=0
            ))

        # 5. Sort by absolute contribution and assign rank
        items.sort(key=lambda x: x.absoluteContribution, reverse=True)
        for rank_idx, item in enumerate(items, start=1):
            item.rank = rank_idx

        # 6. Partition into Top Positive and Top Negative
        top_pos = [it for it in items if it.direction == ContributionDirection.POSITIVE]
        top_neg = [it for it in items if it.direction == ContributionDirection.NEGATIVE]

        explanation = SHAPExplanation(
            predictionId=prediction_id,
            modelName=model_name,
            modelVersion=model_version,
            baseValue=round(base_val, 4),
            baseValueFormatted=f"{round(base_val * 100, 1)}%",
            predictionValue=round(pred_val, 4),
            predictionValueFormatted=f"{round(pred_val * 100, 1)}%",
            features=items,
            topPositiveFeatures=top_pos,
            topNegativeFeatures=top_neg
        )

        self.history.append(explanation)
        self._persist_explanation(explanation)
        return explanation

    def _persist_explanation(self, explanation: SHAPExplanation):
        existing = []
        if SHAP_FILE.exists():
            try:
                with open(SHAP_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(explanation.model_dump())
        existing = existing[-100:]
        with open(SHAP_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.explainers.clear()
        self.history.clear()
        if SHAP_FILE.exists():
            try:
                SHAP_FILE.unlink()
            except Exception:
                pass

shap_explainer_engine = SHAPExplainerEngine()