from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ThreatClassEnum(str, Enum):
    NORMAL = "NORMAL"
    THREAT = "THREAT"

class PredictedAttackCategory(str, Enum):
    NORMAL = "NORMAL"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE_LIKE = "BRUTE_FORCE_LIKE"
    DOS_LIKE = "DOS_LIKE"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT_LIKE = "LATERAL_MOVEMENT_LIKE"
    EXFILTRATION_LIKE = "EXFILTRATION_LIKE"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"

class RiskLevelEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class PredictionStatusEnum(str, Enum):
    PENDING = "PENDING"
    PREDICTED = "PREDICTED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    REJECTED = "REJECTED"
    ERROR = "ERROR"

class PredictionEvidence(BaseModel):
    topContributingFeatures: List[str] = Field(default_factory=list)
    featureValues: Dict[str, float] = Field(default_factory=dict)
    rationale: str = "Statistical anomaly threshold exceeded"

class AttackPrediction(BaseModel):
    predictionId: str = Field(default_factory=lambda: f"PRED-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    deviceId: str = "UNKNOWN"
    source: str
    destination: str
    threatProbability: float = Field(default=0.0, ge=0.0, le=1.0)
    threatClass: ThreatClassEnum = ThreatClassEnum.NORMAL
    predictedCategory: PredictedAttackCategory = PredictedAttackCategory.NORMAL
    categoryConfidence: float = Field(default=0.0, ge=0.0, le=1.0)
    riskScore: float = Field(default=0.0, ge=0.0, le=100.0)
    riskLevel: RiskLevelEnum = RiskLevelEnum.LOW
    modelName: str = "xgboost"
    modelVersion: str = "1.0.0"
    featureVersion: str = "feat-v1"
    evidence: PredictionEvidence = Field(default_factory=PredictionEvidence)
    predictionStatus: PredictionStatusEnum = PredictionStatusEnum.PREDICTED
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "predictionId": self.predictionId,
            "timestamp": self.timestamp,
            "threatProbability": f"{round(self.threatProbability * 100, 1)}%",
            "threatClass": self.threatClass.value,
            "predictedCategory": self.predictedCategory.value,
            "categoryConfidence": f"{round(self.categoryConfidence * 100, 1)}%",
            "riskScore": round(self.riskScore, 1),
            "riskLevel": self.riskLevel.value,
            "status": self.predictionStatus.value
        }