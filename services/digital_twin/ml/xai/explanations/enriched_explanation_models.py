from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.ml.xai.shap.shap_models import FeatureSHAPItem

class EnrichedPredictionExplanation(BaseModel):
    explanationId: str = Field(default_factory=lambda: f"EXP-{uuid.uuid4().hex[:8].upper()}")
    predictionId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Prediction Target Context
    threatProbability: float
    threatProbabilityFormatted: str
    predictedCategory: str
    categoryConfidence: float
    categoryConfidenceFormatted: str
    riskLevel: str

    # Tiered Explanations
    summary: str
    detailedExplanation: str
    technicalExplanation: str

    # Structured Attributions
    topPositiveContributors: List[FeatureSHAPItem]
    topNegativeContributors: List[FeatureSHAPItem]
    supportingEvidence: List[str]

    confidence: str = "HIGH"
    limitations: str = "This explanation describes model behaviour and does not prove that an attack occurred."

    def to_formatted_display(self) -> str:
        return (
            "================================================================================\n"
            "                      PREDICTION EXPLANATION REPORT                             \n"
            "================================================================================\n"
            f"Explanation ID      : {self.explanationId}\n"
            f"Prediction ID       : {self.predictionId}\n"
            f"Threat Probability  : {self.threatProbabilityFormatted} ({self.predictedCategory})\n"
            f"Risk Level          : {self.riskLevel}\n"
            f"Category Confidence : {self.categoryConfidenceFormatted}\n\n"
            f"[EXECUTIVE SUMMARY]\n{self.summary}\n\n"
            f"[DETAILED REASONING]\n{self.detailedExplanation}\n\n"
            f"[TECHNICAL BREAKDOWN]\n{self.technicalExplanation}\n\n"
            f"[OPERATIONAL LIMITATIONS]\n{self.limitations}\n"
            "================================================================================"
        )