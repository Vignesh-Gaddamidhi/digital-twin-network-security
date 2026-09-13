from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ContributionDirection(str, Enum):
    POSITIVE = "POSITIVE"  # Pushes toward THREAT
    NEGATIVE = "NEGATIVE"  # Pushes toward NORMAL / benign
    NEUTRAL = "NEUTRAL"

class FeatureSHAPItem(BaseModel):
    featureName: str
    featureValue: float
    shapValue: float
    shapValueFormatted: str
    direction: ContributionDirection
    absoluteContribution: float
    rank: int

class SHAPExplanation(BaseModel):
    explanationId: str = Field(default_factory=lambda: f"SHAP-{uuid.uuid4().hex[:8].upper()}")
    predictionId: str
    modelName: str
    modelVersion: str = "1.0.0"
    baseValue: float
    baseValueFormatted: str
    predictionValue: float
    predictionValueFormatted: str
    features: List[FeatureSHAPItem]
    topPositiveFeatures: List[FeatureSHAPItem]
    topNegativeFeatures: List[FeatureSHAPItem]
    generatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_summary_string(self) -> str:
        pos_str = ", ".join(f"{f.featureName} ({f.shapValueFormatted})" for f in self.topPositiveFeatures[:3])
        neg_str = ", ".join(f"{f.featureName} ({f.shapValueFormatted})" for f in self.topNegativeFeatures[:2]) if self.topNegativeFeatures else "None"
        return (
            f"SHAP Explanation ID: {self.explanationId} (Prediction: {self.predictionId})\n"
            f"Base Expected Value: {self.baseValueFormatted} -> Prediction: {self.predictionValueFormatted}\n"
            f"Top Threat Drivers (Positive): {pos_str}\n"
            f"Top Mitigators     (Negative): {neg_str}"
        )