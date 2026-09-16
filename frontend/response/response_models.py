from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

class ResponseActionType(str, Enum):
    ISOLATE_DEVICE = "ISOLATE_DEVICE"
    BLOCK_CONNECTION = "BLOCK_CONNECTION"
    DISABLE_SERVICE = "DISABLE_SERVICE"
    QUARANTINE_ENDPOINT = "QUARANTINE_ENDPOINT"
    INCREASE_SECURITY_LEVEL = "INCREASE_SECURITY_LEVEL"
    MARK_DEVICE_AT_RISK = "MARK_DEVICE_AT_RISK"

class ExecutionMode(str, Enum):
    SIMULATION = "SIMULATION"
    DRY_RUN = "DRY_RUN"
    REAL_WORLD_DISARMED = "REAL_WORLD_DISARMED"

class ResponseStatus(str, Enum):
    RECOMMENDED = "RECOMMENDED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTED = "EXECUTED"
    ROLLED_BACK = "ROLLED_BACK"
    REJECTED = "REJECTED"
    FAILED = "FAILED"

class SimulatedResponseRecord(BaseModel):
    responseId: str = Field(default_factory=lambda: f"RSP-{uuid.uuid4().hex[:8].upper()}")
    actionType: ResponseActionType
    reason: str
    triggeringAlertId: str
    triggeringPredictionId: str
    riskScore: float
    affectedDeviceId: str
    targetPort: Optional[int] = None
    targetLinkId: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previousState: str
    newState: str
    operator: str = "SOC_ANALYST_AUTO"
    mode: ExecutionMode = ExecutionMode.SIMULATION
    status: ResponseStatus = ResponseStatus.EXECUTED
    result: str
    rollbackData: Dict[str, Any] = Field(default_factory=dict)
    auditEntryId: str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}")

class ResponseRecommendation(BaseModel):
    recommendationId: str = Field(default_factory=lambda: f"REC-{uuid.uuid4().hex[:6].upper()}")
    actionType: ResponseActionType
    targetDeviceId: str
    suggestedReason: str
    projectedRiskReduction: float
    confidenceScore: float
    requiresManualApproval: bool = False