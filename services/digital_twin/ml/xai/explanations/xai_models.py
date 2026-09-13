from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ExplanationStatusEnum(str, Enum):
    PENDING = "PENDING"
    GENERATED = "GENERATED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"

class FeatureAttribution(BaseModel):
    featureName: str
    featureValue: float
    contribution: float  # Phi value (positive elevates threat, negative dampens)
    contributionFormatted: str
    direction: str       # ESCALATING (+), MITIGATING (-)
    rank: int

class PredictionExplanation(BaseModel):
    explanationId: str = Field(default_factory=lambda: f"XAI-{uuid.uuid4().hex[:8].upper()}")
    predictionId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Model & Feature Lineage
    modelName: str
    modelVersion: str = "1.0.0"
    featureVersion: str = "feature-v1.0"

    # Prediction Target Context
    prediction: str = "THREAT"  # THREAT, NORMAL
    threatProbability: float
    threatProbabilityFormatted: str
    predictedCategory: str = "UNKNOWN"
    categoryConfidence: float = 1.0
    categoryConfidenceFormatted: str = "100.0%"
    riskScore: float = 0.0
    riskLevel: str = "LOW"

    # Level 1: Global Feature Importance
    globalFeatureImportance: Dict[str, float] = Field(default_factory=dict)

    # Level 2: Local Feature Attributions
    baseValue: float = 0.50  # E[f(x)]
    featureValues: Dict[str, float] = Field(default_factory=dict)
    featureContributions: Dict[str, float] = Field(default_factory=dict)
    topPositiveFeatures: List[FeatureAttribution] = Field(default_factory=list)
    topNegativeFeatures: List[FeatureAttribution] = Field(default_factory=list)

    # Level 3: Evidence & Natural Language Synthesis
    evidence: List[str] = Field(default_factory=list)
    naturalLanguageExplanation: str = ""
    explanationStatus: ExplanationStatusEnum = ExplanationStatusEnum.GENERATED

    def to_summary_string(self) -> str:
        pos_str = ", ".join(f"{f.featureName} ({f.contributionFormatted})" for f in self.topPositiveFeatures[:3])
        neg_str = ", ".join(f"{f.featureName} ({f.contributionFormatted})" for f in self.topNegativeFeatures[:2]) if self.topNegativeFeatures else "None"
        return (
            f"Explanation ID: {self.explanationId}\n"
            f"Prediction ID : {self.predictionId}\n"
            f"Assessment    : {self.predictedCategory} (Probability: {self.threatProbabilityFormatted}, Risk: {self.riskLevel})\n"
            f"Top Escalating: {pos_str}\n"
            f"Top Mitigating: {neg_str}\n"
            f"Reasoning     : {self.naturalLanguageExplanation}\n"
            f"Status        : {self.explanationStatus.value}"
        )