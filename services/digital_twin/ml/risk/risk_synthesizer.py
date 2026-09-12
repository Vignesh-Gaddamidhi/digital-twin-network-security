from typing import Dict, Any, Tuple
from services.digital_twin.ml.prediction.prediction_models import (
    PredictedAttackCategory, RiskLevelEnum, PredictionStatusEnum
)

class ContextualRiskSynthesizer:
    """Combines statistical ML probabilities with device context and operational exposure."""

    CATEGORY_SEVERITY_WEIGHTS = {
        PredictedAttackCategory.NORMAL: 0.0,
        PredictedAttackCategory.PORT_SCAN: 0.35,
        PredictedAttackCategory.BEACONING: 0.50,
        PredictedAttackCategory.DNS_ANOMALY: 0.60,
        PredictedAttackCategory.BRUTE_FORCE_LIKE: 0.70,
        PredictedAttackCategory.DOS_LIKE: 0.80,
        PredictedAttackCategory.LATERAL_MOVEMENT_LIKE: 0.85,
        PredictedAttackCategory.EXFILTRATION_LIKE: 0.95,
        PredictedAttackCategory.NETWORK_INTRUSION: 0.75
    }

    CONFIDENCE_THRESHOLD = 0.80

    def calculate_risk(
        self,
        threat_prob: float,
        category: PredictedAttackCategory,
        confidence: float,
        device_criticality: float = 0.5,
        network_exposure: float = 0.5
    ) -> Tuple[float, RiskLevelEnum, PredictionStatusEnum]:
        # If threat probability is minimal, risk is baseline LOW
        if threat_prob < 0.15:
            return 5.0, RiskLevelEnum.LOW, PredictionStatusEnum.HIGH_CONFIDENCE

        cat_weight = self.CATEGORY_SEVERITY_WEIGHTS.get(category, 0.5)
        crit = max(0.1, min(1.0, device_criticality))
        expo = max(0.1, min(1.0, network_exposure))

        # Composite formulation:
        # Threat Probability: 40%
        # Category Confidence: 15%
        # Attack Category Impact: 25%
        # Asset Criticality & Exposure: 20%
        raw_score = (
            (threat_prob * 40.0) +
            (confidence * 15.0) +
            (cat_weight * 25.0) +
            (((crit + expo) / 2.0) * 20.0)
        )
        score = round(max(0.0, min(100.0, raw_score)), 1)

        # Map to Risk Level
        if score < 30.0:
            level = RiskLevelEnum.LOW
        elif score < 60.0:
            level = RiskLevelEnum.MEDIUM
        elif score < 85.0:
            level = RiskLevelEnum.HIGH
        else:
            level = RiskLevelEnum.CRITICAL

        # Map to Prediction Status Lifecycle
        if confidence >= self.CONFIDENCE_THRESHOLD:
            status = PredictionStatusEnum.HIGH_CONFIDENCE
        else:
            status = PredictionStatusEnum.LOW_CONFIDENCE

        return score, level, status

risk_synthesizer = ContextualRiskSynthesizer()