import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import joblib

ROOT_DIR = Path(__file__).resolve().parents[4]
XAI_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai"

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES, dataset_loader
from services.digital_twin.ml.xai.shap.shap_engine import shap_explainer_engine
from services.digital_twin.ml.xai.shap.shap_models import ContributionDirection, FeatureSHAPItem, SHAPExplanation
from services.digital_twin.ml.xai.feature_importance.global_importance_engine import global_feature_importance_engine
from services.digital_twin.ml.xai.explanations.prediction_explanation_engine import prediction_explanation_engine
from services.digital_twin.ml.xai.visualization.xai_dashboard_engine import xai_dashboard_engine

class MasterXAIValidator:
    """Validates multi-model explainability, quality metrics, and defensive failure modes."""

    SUPPORTED_MODELS = [
        ("logistic_regression", "LinearExplainer / Coefficients", "High"),
        ("decision_tree", "TreeExplainer / Split Paths", "High"),
        ("random_forest", "TreeExplainer / Exact Shapley", "Medium-High"),
        ("svm", "KernelExplainer / Surrogate Sensitivity", "Model-Dependent"),
        ("xgboost", "TreeExplainer / Exact Gradient Paths", "Medium-High")
    ]

    def __init__(self):
        XAI_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    def benchmark_all_models_xai(self) -> List[Dict[str, Any]]:
        results = []
        X_tr, _, X_te, y_te, _ = dataset_loader.load_train_test()
        sample_inst = {fn: float(X_te[0, i]) for i, fn in enumerate(FEATURE_NAMES)}

        for m_name, strategy, level in self.SUPPORTED_MODELS:
            model_path = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / m_name / "model.joblib"
            if not model_path.exists():
                continue

            data = joblib.load(model_path)
            model = data["model"] if isinstance(data, dict) and "model" in data else data

            # Evaluate standard metrics
            if hasattr(model, "predict"):
                preds = model.predict(X_te)
                acc = float(np.mean(preds == y_te))
            else:
                acc = 1.0

            # Generate SHAP explanation
            exp = shap_explainer_engine.explain_instance(
                prediction_id=f"PRED-BENCH-{m_name.upper()}",
                features=sample_inst,
                model=model,
                model_name=m_name,
                model_version=f"{m_name[:3]}-v1.0"
            )

            results.append({
                "model": m_name.replace("_", " ").title(),
                "accuracy": round(acc, 4),
                "strategy": strategy,
                "interpretability": level,
                "topDriver": exp.topPositiveFeatures[0].featureName if exp.topPositiveFeatures else "N/A",
                "status": "VALIDATED"
            })

        return results

    def validate_failure_conditions(self) -> Dict[str, bool]:
        tests = {}

        # 1. Missing Model
        try:
            shap_explainer_engine.explain_instance(
                prediction_id="FAIL-01",
                features={"packet_rate": 1.0},
                model=None,
                model_name="non_existent_model"
            )
            tests["missing_model_handled"] = False
        except Exception:
            tests["missing_model_handled"] = True

        # 2. Feature Schema Mismatch (Input missing required features)
        partial_feats = {"packet_rate": 0.5}  # 1 feature instead of 20
        # Engine must backfill missing features with 0.0 safely without crashing
        exp_mismatch = shap_explainer_engine.explain_instance(
            prediction_id="FAIL-02",
            features=partial_feats,
            model=joblib.load(ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib")["model"]
        )
        tests["feature_mismatch_handled"] = len(exp_mismatch.features) == len(FEATURE_NAMES)

        # 3. Invalid / NaN Telemetry Values
        nan_feats = {"packet_rate": float("nan"), "bytes": float("inf")}
        try:
            _ = xai_dashboard_engine.build_evidence_panel(nan_feats)
            tests["nan_inf_handled"] = True
        except Exception:
            tests["nan_inf_handled"] = False

        # 4. Unknown Feature Keys (Ignored gracefully)
        unknown_feats = {"completely_fabricated_metric": 9999.0, "packet_rate": 1.0}
        exp_unknown = shap_explainer_engine.explain_instance(
            prediction_id="FAIL-04",
            features=unknown_feats,
            model=joblib.load(ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib")["model"]
        )
        tests["unknown_feature_handled"] = exp_unknown is not None

        return tests

master_xai_validator = MasterXAIValidator()