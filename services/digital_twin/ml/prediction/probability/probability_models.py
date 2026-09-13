from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ThreatClassEnum(str, Enum):
    NORMAL = "NORMAL"
    THREAT = "THREAT"

class ThreatProbabilityOutput(BaseModel):
    predictionId: str = Field(default_factory=lambda: f"PRED-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    threatProbability: float = Field(..., ge=0.0, le=1.0)
    threatProbabilityFormatted: str
    decisionThreshold: float = 0.50
    threatClass: ThreatClassEnum
    modelName: str
    rawScores: Optional[Dict[str, float]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_display_string(self) -> str:
        return (
            f"Prediction ID: {self.predictionId}\n"
            f"Threat Probability: {self.threatProbability:.2f} ({self.threatProbabilityFormatted})\n"
            f"Threat Class: {self.threatClass.value}\n"
            f"Model: {self.modelName}"
        )