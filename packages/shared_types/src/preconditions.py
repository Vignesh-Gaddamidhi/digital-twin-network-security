from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class PreconditionTypeEnum(str, Enum):
    DEVICE_EXISTS = "DEVICE_EXISTS"
    SERVICE_EXISTS = "SERVICE_EXISTS"
    PORT_STATE = "PORT_STATE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SIMULATION_STATE = "SIMULATION_STATE"

class PreconditionOperatorEnum(str, Enum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    IN_LIST = "IN_LIST"
    GREATER_THAN = "GREATER_THAN"

class PreconditionRuleModel(BaseModel):
    preconditionId: str = Field(default_factory=lambda: f"pre-{uuid.uuid4().hex[:6]}")
    type: PreconditionTypeEnum
    target: str = Field(..., description="Target identifier (e.g. device_id, device_id:port)")
    operator: PreconditionOperatorEnum = PreconditionOperatorEnum.EQUALS
    expectedValue: Any = Field(..., description="Expected value: True, 'OPEN', 'SSH', etc.")
    required: bool = Field(default=True, description="If True, failure blocks scenario execution")
    description: str = "Precondition constraint"

class PreconditionCheckDetail(BaseModel):
    preconditionId: str
    type: PreconditionTypeEnum
    target: str
    passed: bool
    observedValue: Any
    expectedValue: Any
    reason: Optional[str] = None

class PreconditionValidationReport(BaseModel):
    scenarioId: str
    targetDevice: str
    isValid: bool
    totalRulesEvaluated: int
    passedRulesCount: int
    failedRulesCount: int
    failureReasons: List[str] = Field(default_factory=list)
    details: List[PreconditionCheckDetail] = Field(default_factory=list)
    evaluatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())