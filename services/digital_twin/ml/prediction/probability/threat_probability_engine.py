import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
PREDICTIONS_ARTIFACT_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "predictions"
PREDICTIONS_FILE = PREDICTIONS_ARTIFACT_DIR / "threat_probabilities.json"

from services.digital_twin.ml.prediction.probability.probability_models import (
    ThreatProbabilityOutput, ThreatClassEnum
)
from services.digital_twin.ml.models.base_classifier import BaseAttackClassifier

class ThreatProbabilityEngine:
    """Extracts, validates, and standardizes continuous threat probabilities from ML models."""

    DEFAULT_THRESHOLD = 0.50

    def __init__(self, artifact_dir: Path = PREDICTIONS_ARTIFACT_DIR):
        self.artifact_dir = artifact_dir
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.prediction_history: List[ThreatProbabilityOutput] = []

    @staticmethod
    def validate_probability(prob: float) -> float:
        if prob is None or (isinstance(prob, float) and math.isnan(prob)):
            raise ValueError("Threat probability contains invalid NaN or None value.")
        if prob < 0.0 or prob > 1.0:
            raise ValueError(f"Threat probability {prob} out of valid bounds [0.0, 1.0].")
        return float(prob)

    def extract_threat_probability(
        self,
        model: Any,
        X: np.ndarray,
        model_name: str = "unknown_model",
        threshold: float = DEFAULT_THRESHOLD,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ThreatProbabilityOutput]:
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # 1. Extract raw probability or continuous score
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)
            # Positive class is index 1
            threat_probs = probs[:, 1] if probs.ndim == 2 and probs.shape[1] > 1 else probs.flatten()
        elif hasattr(model, "decision_function"):
            df = model.decision_function(X)
            # Map signed distance to [0, 1] sigmoid probability
            threat_probs = 1.0 / (1.0 + np.exp(-df))
        else:
            preds = model.predict(X)
            threat_probs = preds.astype(float)

        outputs = []
        for idx, raw_p in enumerate(threat_probs):
            p = self.validate_probability(round(float(raw_p), 4))
            t_class = ThreatClassEnum.THREAT if p >= threshold else ThreatClassEnum.NORMAL

            out = ThreatProbabilityOutput(
                threatProbability=p,
                threatProbabilityFormatted=f"{round(p * 100, 1)}%",
                decisionThreshold=threshold,
                threatClass=t_class,
                modelName=model_name,
                rawScores={"raw_anomaly_score": float(raw_p)},
                metadata=metadata or {}
            )
            outputs.append(out)
            self.prediction_history.append(out)

        # Append to persistent JSON
        self._persist_predictions(outputs)
        return outputs

    def compare_models_on_test_set(
        self,
        models_dict: Dict[str, Any],
        X_test: np.ndarray,
        y_test: np.ndarray,
        threshold: float = DEFAULT_THRESHOLD
    ) -> List[Dict[str, Any]]:
        comparison_results = []
        for m_name, m_inst in models_dict.items():
            preds = self.extract_threat_probability(m_inst, X_test, model_name=m_name, threshold=threshold)
            for i, p_out in enumerate(preds):
                comparison_results.append({
                    "sampleIndex": i,
                    "model": m_name,
                    "actualLabel": "ANOMALOUS" if int(y_test[i]) == 1 else "NORMAL",
                    "threatProbability": p_out.threatProbability,
                    "threatProbabilityFormatted": p_out.threatProbabilityFormatted,
                    "predictedClass": p_out.threatClass.value,
                    "isCorrect": (p_out.threatClass == ThreatClassEnum.THREAT and int(y_test[i]) == 1) or
                                 (p_out.threatClass == ThreatClassEnum.NORMAL and int(y_test[i]) == 0)
                })
        return comparison_results

    def _persist_predictions(self, records: List[ThreatProbabilityOutput]):
        existing = []
        if PREDICTIONS_FILE.exists():
            try:
                with open(PREDICTIONS_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.extend([r.model_dump() for r in records])
        # Retain last 200 records to prevent unbounded growth
        existing = existing[-200:]
        with open(PREDICTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.prediction_history.clear()
        if PREDICTIONS_FILE.exists():
            try:
                PREDICTIONS_FILE.unlink()
            except Exception:
                pass

threat_probability_engine = ThreatProbabilityEngine()