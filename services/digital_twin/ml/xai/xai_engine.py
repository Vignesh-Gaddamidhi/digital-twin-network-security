import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import joblib

ROOT_DIR = Path(__file__).resolve().parents[4]
XAI_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai"
EXPLANATIONS_FILE = XAI_ARTIFACTS_DIR / "prediction_explanations.json"

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES
from services.digital_twin.ml.xai.explanations.xai_models import (
    ExplanationStatusEnum, FeatureAttribution, PredictionExplanation
)

class BaseXAIEngine:
    """Core Explainable AI Engine providing Global, Local, and Natural Language explanations."""

    DEFAULT_FEATURE_NAMES = FEATURE_NAMES

    def __init__(self, artifacts_dir: Path = XAI_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.history: List[PredictionExplanation] = []

    def extract_global_feature_importance(self, model: Any, feature_names: Optional[List[str]] = None) -> Dict[str, float]:
        feats = feature_names or self.DEFAULT_FEATURE_NAMES
        importances = {}

        # 1. Tree ensembles (Random Forest, Decision Tree, XGBoost)
        if hasattr(model, "feature_importances_"):
            raw_imp = model.feature_importances_
            for fn, imp in zip(feats, raw_imp):
                importances[fn] = round(float(imp), 4)
        # 2. Linear models (Logistic Regression, Linear SVM)
        elif hasattr(model, "coef_"):
            coef = np.abs(model.coef_).flatten()
            norm_coef = coef / (np.sum(coef) + 1e-7)
            for fn, imp in zip(feats, norm_coef):
                importances[fn] = round(float(imp), 4)
        # 3. Fallback uniform attribution
        else:
            uniform_val = round(1.0 / max(1, len(feats)), 4)
            for fn in feats:
                importances[fn] = uniform_val

        # Sort descending
        return dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    def compute_local_attribution(
        self,
        feature_values: Dict[str, float],
        predicted_prob: float,
        global_importances: Dict[str, float],
        base_value: float = 0.50
    ) -> Tuple[Dict[str, float], List[FeatureAttribution], List[FeatureAttribution]]:
        phi_dict: Dict[str, float] = {}
        total_delta = predicted_prob - base_value

        # Distribute the prediction deviation proportionally based on feature deviation and importance
        total_weight = sum(global_importances.values()) + 1e-7
        pos_list: List[FeatureAttribution] = []
        neg_list: List[FeatureAttribution] = []

        for rank, (fn, imp) in enumerate(global_importances.items(), start=1):
            val = float(feature_values.get(fn, 0.0))
            # Directional attribution: positive feature values scale positive delta
            direction_factor = 1.0 if val >= 0.0 else -1.0
            phi_j = round((imp / total_weight) * total_delta * direction_factor, 4)
            phi_dict[fn] = phi_j

            attr = FeatureAttribution(
                featureName=fn,
                featureValue=val,
                contribution=phi_j,
                contributionFormatted=f"{'+' if phi_j >= 0 else ''}{phi_j:.4f}",
                direction="ESCALATING" if phi_j >= 0 else "MITIGATING",
                rank=rank
            )

            if phi_j >= 0:
                pos_list.append(attr)
            else:
                neg_list.append(attr)

        pos_list.sort(key=lambda x: abs(x.contribution), reverse=True)
        neg_list.sort(key=lambda x: abs(x.contribution), reverse=True)

        return phi_dict, pos_list, neg_list

    def synthesize_natural_language_evidence(
        self,
        predicted_category: str,
        threat_probability: float,
        top_positive: List[FeatureAttribution],
        top_negative: List[FeatureAttribution]
    ) -> Tuple[List[str], str]:
        evidence = []
        top_pos_names = [a.featureName for a in top_positive[:3]]

        for a in top_positive[:4]:
            if a.contribution > 0.01:
                evidence.append(
                    f"{a.featureName.replace('_', ' ').capitalize()} contributed positively ({a.contributionFormatted}) with observed value {a.featureValue:.2f}."
                )

        for a in top_negative[:2]:
            if a.contribution < -0.01:
                evidence.append(
                    f"{a.featureName.replace('_', ' ').capitalize()} acted as mitigating baseline evidence ({a.contributionFormatted})."
                )

        if not evidence:
            evidence.append("All network telemetry features remained within normal baseline boundaries.")

        # Human-readable summary sentence
        pos_desc = ", ".join(top_pos_names) if top_pos_names else "general baseline drift"
        if threat_probability >= 0.50:
            nl = (
                f"Threat probability increased to {round(threat_probability * 100, 1)}% ({predicted_category}) "
                f"primarily because {pos_desc.replace('_', ' ')} exhibited elevated divergence from the learned normal pattern."
            )
        else:
            nl = (
                f"Network behavior classified as normal (threat probability: {round(threat_probability * 100, 1)}%) "
                f"with telemetry patterns consistent with benign traffic."
            )

        return evidence, nl

    def explain_prediction(
        self,
        prediction_id: str,
        feature_values: Dict[str, float],
        threat_probability: float,
        predicted_category: str,
        category_confidence: float = 0.90,
        risk_score: float = 50.0,
        risk_level: str = "MEDIUM",
        model: Optional[Any] = None,
        model_name: str = "random_forest",
        model_version: str = "rf-v1.0",
        feature_version: str = "feature-v1.0",
        feature_names: Optional[List[str]] = None
    ) -> PredictionExplanation:
        try:
            feats = feature_names or self.DEFAULT_FEATURE_NAMES

            # 1. Level 1: Global Importances
            global_imp = self.extract_global_feature_importance(model, feature_names=feats)

            # 2. Level 2: Local Feature Attribution
            phi_dict, pos_attrs, neg_attrs = self.compute_local_attribution(
                feature_values=feature_values,
                predicted_prob=threat_probability,
                global_importances=global_imp,
                base_value=0.50
            )

            # 3. Level 3: Evidence & Natural Language Synthesis
            evidence, nl_summary = self.synthesize_natural_language_evidence(
                predicted_category=predicted_category,
                threat_probability=threat_probability,
                top_positive=pos_attrs,
                top_negative=neg_attrs
            )

            explanation = PredictionExplanation(
                predictionId=prediction_id,
                modelName=model_name,
                modelVersion=model_version,
                featureVersion=feature_version,
                prediction="THREAT" if threat_probability >= 0.50 else "NORMAL",
                threatProbability=threat_probability,
                threatProbabilityFormatted=f"{round(threat_probability * 100, 1)}%",
                predictedCategory=predicted_category,
                categoryConfidence=category_confidence,
                categoryConfidenceFormatted=f"{round(category_confidence * 100, 1)}%",
                riskScore=risk_score,
                riskLevel=risk_level,
                globalFeatureImportance=global_imp,
                baseValue=0.50,
                featureValues={k: float(feature_values.get(k, 0.0)) for k in feats},
                featureContributions=phi_dict,
                topPositiveFeatures=pos_attrs[:5],
                topNegativeFeatures=neg_attrs[:3],
                evidence=evidence,
                naturalLanguageExplanation=nl_summary,
                explanationStatus=ExplanationStatusEnum.GENERATED
            )

            self.history.append(explanation)
            self._persist_explanation(explanation)
            return explanation

        except Exception as e:
            fallback = PredictionExplanation(
                predictionId=prediction_id,
                modelName=model_name,
                modelVersion=model_version,
                featureVersion=feature_version,
                prediction="ERROR",
                threatProbability=threat_probability,
                threatProbabilityFormatted=f"{round(threat_probability * 100, 1)}%",
                predictedCategory=predicted_category,
                naturalLanguageExplanation=f"Failed to generate explanation: {str(e)}",
                explanationStatus=ExplanationStatusEnum.FAILED
            )
            return fallback

    def _persist_explanation(self, explanation: PredictionExplanation):
        existing = []
        if EXPLANATIONS_FILE.exists():
            try:
                with open(EXPLANATIONS_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(explanation.model_dump())
        existing = existing[-100:]  # Preserve last 100 explanations
        with open(EXPLANATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        if EXPLANATIONS_FILE.exists():
            try:
                EXPLANATIONS_FILE.unlink()
            except Exception:
                pass

base_xai_engine = BaseXAIEngine()