import time
import json
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]

from services.digital_twin.ml.prediction.prediction_models import (
    AttackPrediction, ThreatClassEnum, PredictedAttackCategory,
    RiskLevelEnum, PredictionStatusEnum, PredictionEvidence
)
from services.digital_twin.ml.prediction.probability.threat_probability_engine import threat_probability_engine
from services.digital_twin.ml.prediction.classification.attack_category_engine import attack_category_engine
from services.digital_twin.ml.prediction.confidence.confidence_engine import prediction_confidence_engine
from services.digital_twin.ml.prediction.confidence.confidence_models import ConfidenceTierEnum
from services.digital_twin.ml.risk.prediction_risk_engine import prediction_risk_engine
from services.digital_twin.ml.risk.risk_models import (
    DeviceCriticalityEnum, NetworkExposureEnum, VulnerabilityStatusEnum,
    OperationalRiskLevel, PredictionRiskAssessment
)
from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES
from services.digital_twin.ml.prediction.defensive_prediction_guard import sanitize_and_measure_input, DefensiveValidationError

class TwinDeviceSecurityState:
    """Represents the live operational security state of a device in the Digital Twin."""
    def __init__(self, device_id: str):
        self.deviceId = device_id
        self.state: str = "NORMAL"  # NORMAL, SUSPICIOUS, AT_RISK, COMPROMISED
        self.threatProbability: float = 0.0
        self.threatProbabilityFormatted: str = "0.0%"
        self.predictedCategory: str = "NORMAL"
        self.predictionConfidence: float = 1.0
        self.predictionConfidenceFormatted: str = "100.0%"
        self.riskScore: float = 0.0
        self.riskLevel: str = "LOW"
        self.lastPredictionId: Optional[str] = None
        self.lastUpdated: str = datetime.now(timezone.utc).isoformat()
        self.predictionHistory: List[Dict[str, Any]] = []

    def update_state(self, assessment: PredictionRiskAssessment, confidence_tier: str):
        self.threatProbability = assessment.threatProbability
        self.threatProbabilityFormatted = assessment.threatProbabilityFormatted
        self.predictedCategory = assessment.predictedCategory
        self.predictionConfidence = assessment.categoryConfidence
        self.predictionConfidenceFormatted = assessment.categoryConfidenceFormatted
        self.riskScore = assessment.riskScore
        self.riskLevel = assessment.riskLevel.value
        self.lastPredictionId = assessment.predictionId
        self.lastUpdated = datetime.now(timezone.utc).isoformat()

        # State transition rule
        if self.state != "COMPROMISED":
            if assessment.riskLevel in (OperationalRiskLevel.HIGH, OperationalRiskLevel.CRITICAL) and self.predictionConfidence >= 0.70:
                self.state = "AT_RISK"
            elif assessment.threatProbability >= 0.50 or assessment.riskScore >= 30.0:
                self.state = "SUSPICIOUS"
            else:
                self.state = "NORMAL"

        # Preserve immutable history
        self.predictionHistory.append({
            "predictionId": assessment.predictionId,
            "timestamp": self.lastUpdated,
            "threatProbability": assessment.threatProbabilityFormatted,
            "predictedCategory": assessment.predictedCategory,
            "confidence": assessment.categoryConfidenceFormatted,
            "riskScore": assessment.riskScore,
            "riskLevel": assessment.riskLevel.value,
            "resultingState": self.state
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deviceId": self.deviceId,
            "state": self.state,
            "threatProbability": self.threatProbabilityFormatted,
            "predictedCategory": self.predictedCategory,
            "predictionConfidence": self.predictionConfidenceFormatted,
            "riskScore": self.riskScore,
            "riskLevel": self.riskLevel,
            "lastPredictionId": self.lastPredictionId,
            "lastUpdated": self.lastUpdated,
            "historyCount": len(self.predictionHistory)
        }

class EndToEndAttackPredictionPipeline:
    """Master pipeline orchestrating feature vector parsing, ML prediction, risk scoring, state update, and alerts."""

    def __init__(self):
        self.device_registry: Dict[str, TwinDeviceSecurityState] = {}
        self.alert_log: List[Dict[str, Any]] = []

    def get_or_create_device(self, device_id: str) -> TwinDeviceSecurityState:
        if device_id not in self.device_registry:
            self.device_registry[device_id] = TwinDeviceSecurityState(device_id)
        return self.device_registry[device_id]

    def execute_pipeline(
        self,
        features: Any,
        source: str,
        destination: str,
        device_id: str = "SERVER-01",
        device_criticality: DeviceCriticalityEnum = DeviceCriticalityEnum.HIGH,
        network_exposure: NetworkExposureEnum = NetworkExposureEnum.EXTERNAL_FACING,
        vulnerability_status: VulnerabilityStatusEnum = VulnerabilityStatusEnum.NONE_KNOWN,
        model_name: str = "xgboost"
    ) -> Dict[str, Any]:
        prediction_id = f"pred-{uuid.uuid4().hex[:6]}"
        t_start = time.perf_counter()

        # Defensive Guard Step: Sanitize input and measure feature extraction latency
        try:
            clean_features, feat_latency_ms = sanitize_and_measure_input(features)
        except DefensiveValidationError as e:
            device = self.get_or_create_device(device_id)
            return {
                "predictionId": prediction_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source,
                "destination": destination,
                "threatProbability": "0.0%",
                "threatClass": "ERROR",
                "predictedCategory": "UNKNOWN",
                "categoryConfidence": "0.0%",
                "riskScore": 0.0,
                "riskLevel": "LOW",
                "model": model_name,
                "modelVersion": "xgb-v1.0",
                "featureVersion": "feature-v1.0",
                "predictionStatus": "ERROR",
                "errorDetails": str(e),
                "digitalTwinState": device.to_dict(),
                "alert": None
            }

        try:
            # 1. Feature Vector Construction
            feat_vector = np.array([float(clean_features.get(fn, 0.0)) for fn in FEATURE_NAMES], dtype=np.float32)

            # 2. Multi-Class Classification & Confidence Evaluation
            t_ml = time.perf_counter()
            cat_out = attack_category_engine.classify_behavior(feat_vector, model_name=model_name)
            conf_audit = prediction_confidence_engine.evaluate_confidence(cat_out.classDistribution)
            ml_latency_ms = round((time.perf_counter() - t_ml) * 1000, 3)

            # 3. Threat Probability Estimation
            normal_prob = cat_out.classDistribution.get("NORMAL", 0.0)
            threat_prob = round(float(1.0 - normal_prob), 4)

            # 4. Contextual Risk Assessment
            t_risk = time.perf_counter()
            risk_assessment = prediction_risk_engine.assess_risk(
                prediction_id=prediction_id,
                threat_probability=threat_prob,
                predicted_category=cat_out.predictedCategory.value,
                category_confidence=cat_out.categoryConfidence,
                device_criticality=device_criticality,
                network_exposure=network_exposure,
                vulnerability_status=vulnerability_status
            )
            risk_latency_ms = round((time.perf_counter() - t_risk) * 1000, 3)

            # 5. Update Digital Twin Device Security State
            device = self.get_or_create_device(device_id)
            device.update_state(risk_assessment, conf_audit.confidenceTier.value)

            # 6. Generate Alert if High/Critical Risk
            alert = None
            if risk_assessment.riskLevel in (OperationalRiskLevel.HIGH, OperationalRiskLevel.CRITICAL):
                alert = {
                    "alertId": f"ALT-ML-{uuid.uuid4().hex[:8].upper()}",
                    "alertType": "ML_ATTACK_PREDICTION",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": risk_assessment.riskLevel.value,
                    "deviceId": device_id,
                    "source": source,
                    "destination": destination,
                    "threatProbability": risk_assessment.threatProbabilityFormatted,
                    "predictedCategory": cat_out.predictedCategory.value,
                    "confidence": cat_out.categoryConfidenceFormatted,
                    "risk": risk_assessment.riskLevel.value,
                    "riskScore": risk_assessment.riskScore,
                    "contributingFactors": risk_assessment.contributingFactors
                }
                self.alert_log.append(alert)

            total_latency_ms = round((time.perf_counter() - t_start) * 1000, 3)

            return {
                "predictionId": prediction_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source,
                "destination": destination,
                "threatProbability": risk_assessment.threatProbabilityFormatted,
                "threatClass": "THREAT" if threat_prob >= 0.50 else "NORMAL",
                "predictedCategory": cat_out.predictedCategory.value,
                "categoryConfidence": cat_out.categoryConfidenceFormatted,
                "riskScore": risk_assessment.riskScore,
                "riskLevel": risk_assessment.riskLevel.value,
                "model": model_name,
                "modelVersion": "xgb-v1.0",
                "featureVersion": "feature-v1.0",
                "predictionStatus": conf_audit.confidenceTier.value,
                "latencyBreakdown": {
                    "featureExtractionMs": feat_latency_ms,
                    "mlInferenceMs": ml_latency_ms,
                    "riskAssessmentMs": risk_latency_ms,
                    "totalMs": total_latency_ms
                },
                "digitalTwinState": device.to_dict(),
                "alert": alert
            }
        except Exception as e:
            device = self.get_or_create_device(device_id)
            return {
                "predictionId": prediction_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source,
                "destination": destination,
                "threatProbability": "0.0%",
                "threatClass": "ERROR",
                "predictedCategory": "UNKNOWN",
                "categoryConfidence": "0.0%",
                "riskScore": 0.0,
                "riskLevel": "LOW",
                "model": model_name,
                "modelVersion": "xgb-v1.0",
                "featureVersion": "feature-v1.0",
                "predictionStatus": "ERROR",
                "errorDetails": str(e),
                "digitalTwinState": device.to_dict(),
                "alert": None
            }

    def clear(self):
        self.device_registry.clear()
        self.alert_log.clear()

end_to_end_prediction_pipeline = EndToEndAttackPredictionPipeline()