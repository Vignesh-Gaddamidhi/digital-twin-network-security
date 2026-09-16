from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
import itertools

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum

# Thread-safe monotonic response ID generator
_response_id_counter = itertools.count(1)

def generate_canonical_response_id() -> str:
    now = datetime.now(timezone.utc)
    count = next(_response_id_counter)
    return f"RESP-{now.strftime('%Y%m%d')}-{count:06d}"

class TriggeringAlertReference(BaseModel):
    alertId: str
    eventType: str
    severity: RiskLevelTier
    detectionType: str = "HYBRID_IDS_ML"
    confidence: float
    riskScore: float

class TriggeringPredictionReference(BaseModel):
    predictionId: str
    threatProbability: float
    threatClass: str = "MALICIOUS"
    predictedCategory: str
    categoryConfidence: float
    modelName: str = "RandomForest+LSTM_Ensemble"
    modelVersion: str = "v2.4.0"

class ResponseRiskBreakdown(BaseModel):
    riskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    assetCriticality: float = 1.0
    vulnerabilityFactor: float = 0.8
    attackImpact: float = 1.0

class ResponseResultRecord(BaseModel):
    status: str = "SUCCESS"
    message: str = "Digital Twin state updated successfully"
    twinUpdated: bool = True
    affectedConnections: List[str] = Field(default_factory=list)
    affectedServices: List[str] = Field(default_factory=list)

class CanonicalResponseContract(BaseModel):
    """Canonical, fully validated response model governing automated defensive mutations."""
    responseId: str = Field(default_factory=generate_canonical_response_id)
    action: ResponseActionType
    reason: str
    triggeringAlert: TriggeringAlertReference
    triggeringPrediction: TriggeringPredictionReference
    riskAssessment: ResponseRiskBreakdown
    affectedDevice: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previousState: str
    newState: str
    operator: str = "AUTOMATED_SIMULATION"
    mode: ExecutionModeEnum = ExecutionModeEnum.SIMULATION
    result: ResponseResultRecord = Field(default_factory=ResponseResultRecord)
    auditEntryId: Optional[str] = None
    executionStatus: ResponseStatusEnum = ResponseStatusEnum.RECOMMENDED

    @property
    def status(self) -> ResponseStatusEnum:
        return self.executionStatus

    @property
    def executionMode(self) -> ExecutionModeEnum:
        return self.mode

    @property
    def resultSummary(self) -> str:
        return self.result.message

class ResponseExecutionRecord(BaseModel):
    responseId: str = Field(default_factory=generate_canonical_response_id)
    recommendationId: str = ""
    actionType: ResponseActionType = ResponseActionType.ISOLATE_DEVICE
    affectedDevice: str = ""
    affectedLink: Optional[str] = None
    affectedService: Optional[str] = None
    reason: str = ""
    triggeringAlert: str = ""
    triggeringPrediction: str = ""
    riskScore: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previousState: str = "NORMAL"
    newState: str = "ISOLATED"
    operator: str = "AUTO_DEFENDER_SIMULATOR"
    executionMode: ExecutionModeEnum = ExecutionModeEnum.SIMULATION
    status: ResponseStatusEnum = ResponseStatusEnum.RECOMMENDED
    resultSummary: str = "Initialized"
    auditEntryId: Optional[str] = None
