from enum import Enum
from typing import Dict, Any, List
from pydantic import BaseModel, Field

class ConfidenceTierEnum(str, Enum):
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    MEDIUM_CONFIDENCE = "MEDIUM_CONFIDENCE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"

class ConfidenceThresholdConfig(BaseModel):
    highConfidenceThreshold: float = 0.80
    highSeparationMargin: float = 0.35
    maxNormalizedEntropyForHigh: float = 0.45
    mediumConfidenceThreshold: float = 0.50
    mediumSeparationMargin: float = 0.15

class ConfidenceAuditReport(BaseModel):
    categoryConfidence: float
    confidenceTier: ConfidenceTierEnum
    topCategory: str
    runnerUpCategory: str
    separationMargin: float
    normalizedEntropy: float
    isLowConfidenceWarning: bool
    rationale: str