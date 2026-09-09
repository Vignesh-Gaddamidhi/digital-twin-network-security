from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class IndicatorTypeEnum(str, Enum):
    HIGH_CONNECTION_RATE = "HIGH_CONNECTION_RATE"
    HIGH_FAILED_CONNECTION_RATE = "HIGH_FAILED_CONNECTION_RATE"
    UNUSUAL_PORT_ACTIVITY = "UNUSUAL_PORT_ACTIVITY"
    UNUSUAL_PROTOCOL_DISTRIBUTION = "UNUSUAL_PROTOCOL_DISTRIBUTION"
    PERIODIC_TRAFFIC = "PERIODIC_TRAFFIC"
    TRAFFIC_VOLUME_SPIKE = "TRAFFIC_VOLUME_SPIKE"
    UNUSUAL_DESTINATION = "UNUSUAL_DESTINATION"
    UNUSUAL_DNS_FREQUENCY = "UNUSUAL_DNS_FREQUENCY"
    UNUSUAL_OUTBOUND_VOLUME = "UNUSUAL_OUTBOUND_VOLUME"

class IndicatorDirectionEnum(str, Enum):
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    EQUALS = "EQUALS"
    DEVIATION_EXCEEDS = "DEVIATION_EXCEEDS"

class IndicatorSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ExpectedIndicatorModel(BaseModel):
    indicatorId: str = Field(default_factory=lambda: f"ind-{uuid.uuid4().hex[:6]}")
    type: IndicatorTypeEnum
    description: str
    metric: str
    threshold: float
    direction: IndicatorDirectionEnum = IndicatorDirectionEnum.GREATER_THAN
    severity: IndicatorSeverityEnum = IndicatorSeverityEnum.MEDIUM
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ObservedIndicatorModel(BaseModel):
    indicatorId: str = Field(default_factory=lambda: f"obs-{uuid.uuid4().hex[:6]}")
    type: IndicatorTypeEnum
    metric: str
    observedValue: float
    matchedThreshold: float
    direction: IndicatorDirectionEnum
    severity: IndicatorSeverityEnum
    confidence: float
    triggeredAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)

class IndicatorVerificationReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"rep-ind-{uuid.uuid4().hex[:8]}")
    scenarioId: str
    totalExpected: int
    totalObserved: int
    matchedCount: int
    missedCount: int
    precisionScore: float
    matchedIndicators: List[ObservedIndicatorModel] = Field(default_factory=list)
    missedExpectedIndicators: List[ExpectedIndicatorModel] = Field(default_factory=list)
    evaluatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())