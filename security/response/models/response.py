from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum

class ResponseExecutionRecord(BaseModel):
    responseId: str = Field(default_factory=lambda: f"RSP-{uuid.uuid4().hex[:8].upper()}")
    recommendationId: str
    actionType: ResponseActionType
    affectedDevice: str
    affectedLink: Optional[str] = None
    affectedService: Optional[str] = None
    reason: str
    triggeringAlert: str
    triggeringPrediction: str
    riskScore: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previousState: str
    newState: str
    operator: str = "AUTO_DEFENDER_SIMULATOR"
    executionMode: ExecutionModeEnum = ExecutionModeEnum.SIMULATION
    status: ResponseStatusEnum = ResponseStatusEnum.RECOMMENDED
    resultSummary: str = "Initialized"
    auditEntryId: Optional[str] = None