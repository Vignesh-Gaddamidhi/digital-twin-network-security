from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class DeviceCriticalityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    MISSION_CRITICAL = "MISSION_CRITICAL"

class NetworkExposureEnum(str, Enum):
    INTERNAL_ISOLATED = "INTERNAL_ISOLATED"
    INTERNAL_ROUTABLE = "INTERNAL_ROUTABLE"
    DMZ = "DMZ"
    EXTERNAL_FACING = "EXTERNAL_FACING"

class VulnerabilityStatusEnum(str, Enum):
    NONE_KNOWN = "NONE_KNOWN"
    PATCHED = "PATCHED"
    MITIGATED = "MITIGATED"
    OPEN_UNPATCHED = "OPEN_UNPATCHED"

class OperationalRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskThresholdConfig(BaseModel):
    lowThreshold: float = 30.0
    mediumThreshold: float = 60.0
    highThreshold: float = 85.0

class PredictionRiskAssessment(BaseModel):
    riskId: str = Field(default_factory=lambda: f"RISK-{uuid.uuid4().hex[:8].upper()}")
    predictionId: str
    threatProbability: float
    threatProbabilityFormatted: str
    predictedCategory: str
    categoryConfidence: float
    categoryConfidenceFormatted: str
    riskScore: float = Field(..., ge=0.0, le=100.0)
    riskLevel: OperationalRiskLevel
    contributingFactors: List[str] = Field(default_factory=list)
    explanation: str
    modelVersion: str = "1.0.0"
    riskEngineVersion: str = "v2.0-ml-contextual"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    contextSnapshot: Dict[str, Any] = Field(default_factory=dict)

    def to_summary_string(self) -> str:
        factors_str = "\n".join(f"  - {f}" for f in self.contributingFactors)
        return (
            f"Risk ID: {self.riskId}\n"
            f"Prediction ID: {self.predictionId}\n"
            f"Risk Level: {self.riskLevel.value} (Score: {self.riskScore:.1f})\n"
            f"Contributing Factors:\n{factors_str}\n"
            f"Explanation: {self.explanation}"
        )