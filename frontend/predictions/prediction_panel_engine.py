from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from frontend.predictions.prediction_models import (
    AttackCategoryEnum, ModelMetadata, ShapFeatureContribution, LivePredictionDetail
)

class PredictionPanelEngine:
    """Manages prediction telemetry, dual-horizon evaluation, SHAP waterfall attribution, and XAI narratives."""

    def __init__(self):
        self.cached_prediction: Optional[LivePredictionDetail] = None
        self._seed_default_prediction()

    def _seed_default_prediction(self):
        shaps = [
            ShapFeatureContribution(featureName="connection_frequency", featureValue=145.0, shapValue=0.31, direction="POSITIVE", baselineValue=12.0, relativeImportance=0.36),
            ShapFeatureContribution(featureName="destination_diversity", featureValue=0.88, shapValue=0.22, direction="POSITIVE", baselineValue=0.15, relativeImportance=0.25),
            ShapFeatureContribution(featureName="port_activity", featureValue=18.0, shapValue=0.18, direction="POSITIVE", baselineValue=2.0, relativeImportance=0.21),
            ShapFeatureContribution(featureName="packet_rate", featureValue=420.0, shapValue=0.11, direction="POSITIVE", baselineValue=45.0, relativeImportance=0.13),
            ShapFeatureContribution(featureName="dns_frequency", featureValue=35.0, shapValue=0.05, direction="POSITIVE", baselineValue=10.0, relativeImportance=0.06),
            ShapFeatureContribution(featureName="flow_duration", featureValue=0.12, shapValue=-0.03, direction="NEGATIVE", baselineValue=1.85, relativeImportance=0.03)
        ]

        pos = [s.featureName for s in shaps if s.shapValue > 0]
        neg = [s.featureName for s in shaps if s.shapValue < 0]

        short_exp = (
            "Attack probability increased because connection frequency surged, "
            "destination diversity shifted, and abnormal port activity was observed."
        )

        detailed = [
            "Connection frequency increased significantly (145 conns/min vs 12 baseline).",
            "Destination diversity changed from baseline (probes touching multiple hosts).",
            "Port activity became unusual with rapid scanning on unassigned interfaces.",
            "Packet rate increased moderately (+375 pkts/sec over norm)."
        ]

        self.cached_prediction = LivePredictionDetail(
            predictionId="PRED-001234",
            targetDevice="WEB-01",
            currentThreatProbability=0.72,
            futureThreatProbability=0.87,
            predictedCategory=AttackCategoryEnum.PORT_SCAN,
            confidenceScore=0.91,
            riskLevel=RiskLevelTier.HIGH,
            riskScore=69.60,
            modelInfo=ModelMetadata(
                modelName="Random Forest",
                modelVersion="model-v1.2",
                featureVersion="features-v1.0",
                timeSeriesModel="LSTM",
                predictionHorizonSec=60
            ),
            shapContributions=shaps,
            topPositiveFeatures=pos,
            topNegativeFeatures=neg,
            shortExplanation=short_exp,
            detailedExplanation=detailed
        )

    def get_live_prediction(self, device_id: str = "WEB-01") -> LivePredictionDetail:
        if self.cached_prediction and self.cached_prediction.targetDevice == device_id:
            return self.cached_prediction

        # Dynamic fallback generation for requested device
        tier = RiskLevelTier.CRITICAL if device_id == "DB-01" else RiskLevelTier.MEDIUM
        score = 85.36 if device_id == "DB-01" else 42.0
        cat = AttackCategoryEnum.EXFILTRATION_LIKE if device_id == "DB-01" else AttackCategoryEnum.PORT_SCAN

        return LivePredictionDetail(
            targetDevice=device_id,
            currentThreatProbability=0.88 if device_id == "DB-01" else 0.45,
            futureThreatProbability=0.95 if device_id == "DB-01" else 0.58,
            predictedCategory=cat,
            confidenceScore=0.94,
            riskLevel=tier,
            riskScore=score,
            shortExplanation=f"Prediction generated for device {device_id}.",
            detailedExplanation=[f"Automated risk evaluation on {device_id}."]
        )

    def generate_prediction_with_xai(
        self,
        target_device: str,
        current_prob: float,
        future_prob: float,
        category: AttackCategoryEnum,
        confidence: float,
        shap_values: Optional[Dict[str, float]] = None
    ) -> LivePredictionDetail:
        if not (0.0 <= current_prob <= 1.0) or not (0.0 <= future_prob <= 1.0):
            raise ValueError("Threat probabilities must reside within [0.0, 1.0].")

        # Map SHAP contributions
        contributions: List[ShapFeatureContribution] = []
        if shap_values:
            total_abs = sum(abs(v) for v in shap_values.values()) or 1.0
            for k, val in shap_values.items():
                contributions.append(ShapFeatureContribution(
                    featureName=k,
                    featureValue=100.0,
                    shapValue=val,
                    direction="POSITIVE" if val >= 0 else "NEGATIVE",
                    relativeImportance=round(abs(val) / total_abs, 3)
                ))
            contributions.sort(key=lambda x: abs(x.shapValue), reverse=True)
        else:
            # Graceful fallback when XAI data is missing
            contributions = [
                ShapFeatureContribution(featureName="baseline_deviations", featureValue=1.0, shapValue=0.20, direction="POSITIVE", relativeImportance=1.0)
            ]

        pos = [c.featureName for c in contributions if c.shapValue > 0]
        neg = [c.featureName for c in contributions if c.shapValue < 0]

        reasons = [f"{c.featureName.replace('_', ' ').capitalize()} contributed {'+' if c.shapValue>=0 else ''}{c.shapValue:.2f} to threat score." for c in contributions[:4]]

        risk_score = round(future_prob * 80.0, 2)
        tier = threshold_classifier.classify(risk_score)

        pred = LivePredictionDetail(
            targetDevice=target_device,
            currentThreatProbability=current_prob,
            futureThreatProbability=future_prob,
            predictedCategory=category,
            confidenceScore=confidence,
            riskLevel=tier,
            riskScore=risk_score,
            shapContributions=contributions,
            topPositiveFeatures=pos,
            topNegativeFeatures=neg,
            shortExplanation=f"Threat probability evaluated at {future_prob*100:.0f}% based on {len(pos)} elevated features.",
            detailedExplanation=reasons
        )

        self.cached_prediction = pred
        return pred

prediction_panel_engine = PredictionPanelEngine()