from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class IndicatorSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IndicatorTypeEnum(str, Enum):
    # Port / Scanning Indicators (Day 68, 72)
    UNUSUAL_PORT_ACTIVITY = "UNUSUAL_PORT_ACTIVITY"
    HIGH_UNIQUE_PORT_COUNT = "HIGH_UNIQUE_PORT_COUNT"
    HIGH_FAILED_CONNECTION_RATE = "HIGH_FAILED_CONNECTION_RATE"

    # Authentication Indicators (Day 73)
    HIGH_AUTH_FAILURE_RATE = "HIGH_AUTH_FAILURE_RATE"
    REPEATED_AUTH_FAILURES = "REPEATED_AUTH_FAILURES"
    SHORT_FAILURE_INTERVAL = "SHORT_FAILURE_INTERVAL"
    UNUSUAL_AUTH_PATTERN = "UNUSUAL_AUTH_PATTERN"

    # DoS / Volumetric Indicators (Day 74)
    TRAFFIC_VOLUME_SPIKE = "TRAFFIC_VOLUME_SPIKE"
    HIGH_PACKET_RATE = "HIGH_PACKET_RATE"
    HIGH_CONNECTION_RATE = "HIGH_CONNECTION_RATE"
    HIGH_NETWORK_UTILISATION = "HIGH_NETWORK_UTILISATION"

    # DNS Indicators (Day 75)
    UNUSUAL_DNS_FREQUENCY = "UNUSUAL_DNS_FREQUENCY"
    UNUSUAL_DNS_QUERY_TYPE = "UNUSUAL_DNS_QUERY_TYPE"
    REPEATED_DNS_REQUESTS = "REPEATED_DNS_REQUESTS"
    UNUSUAL_DNS_DISTRIBUTION = "UNUSUAL_DNS_DISTRIBUTION"

    # Beaconing Indicators (Day 76)
    PERIODIC_TRAFFIC = "PERIODIC_TRAFFIC"
    REPEATED_DESTINATION = "REPEATED_DESTINATION"
    REGULAR_TIME_INTERVAL = "REGULAR_TIME_INTERVAL"
    UNUSUAL_CONNECTION_FREQUENCY = "UNUSUAL_CONNECTION_FREQUENCY"

    # Lateral Movement Indicators (Day 77)
    UNUSUAL_DEVICE_SEQUENCE = "UNUSUAL_DEVICE_SEQUENCE"
    NEW_INTERNAL_CONNECTION = "NEW_INTERNAL_CONNECTION"
    MULTI_HOST_CONNECTION_PATTERN = "MULTI_HOST_CONNECTION_PATTERN"
    UNUSUAL_DESTINATION = "UNUSUAL_DESTINATION"
    INCREASED_INTERNAL_CONNECTIONS = "INCREASED_INTERNAL_CONNECTIONS"

    # Data Exfiltration Indicators (Day 78)
    UNUSUAL_OUTBOUND_VOLUME = "UNUSUAL_OUTBOUND_VOLUME"
    HIGH_ENTROPY_EGRESS = "HIGH_ENTROPY_EGRESS"

class IndicatorDirectionEnum(str, Enum):
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"

class ExpectedIndicatorModel(BaseModel):
    indicatorId: str = Field(default_factory=lambda: f"ind-{uuid.uuid4().hex[:6]}")
    type: IndicatorTypeEnum
    description: str
    metric: str
    threshold: float
    direction: IndicatorDirectionEnum = IndicatorDirectionEnum.GREATER_THAN
    tolerancePct: float = Field(default=0.0, ge=0.0, le=100.0)
    severity: Union[IndicatorSeverityEnum, str] = IndicatorSeverityEnum.MEDIUM
    confidence: float = 1.0

class ObservedIndicatorModel(BaseModel):
    indicatorId: str = Field(default_factory=lambda: f"obs-{uuid.uuid4().hex[:6]}")
    type: IndicatorTypeEnum
    observedValue: float
    metric: str
    confidence: float = 1.0
    detectedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)

class IndicatorEvaluationResult(BaseModel):
    indicatorId: str
    type: IndicatorTypeEnum
    expectedMetric: str
    expectedThreshold: float
    observedValue: float
    isMatched: bool
    deviationPct: float = 0.0
    direction: IndicatorDirectionEnum = IndicatorDirectionEnum.GREATER_THAN
    severity: Union[IndicatorSeverityEnum, str] = IndicatorSeverityEnum.MEDIUM
    details: Dict[str, Any] = Field(default_factory=dict)

class IndicatorVerificationReport(BaseModel):
    scenarioId: str
    totalExpected: int
    matchedCount: int
    missedCount: int = 0
    precisionScore: float = 1.0
    matchPercentage: float = 0.0
    isMatchSuccessful: bool = False
    matchedIndicators: List[ObservedIndicatorModel] = Field(default_factory=list)
    missedExpectedIndicators: List[ExpectedIndicatorModel] = Field(default_factory=list)
    evaluatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Compatibility aliases
    matchRate: Optional[float] = None
    passed: Optional[bool] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.missedCount and self.missedExpectedIndicators:
            self.missedCount = len(self.missedExpectedIndicators)
        elif not self.missedCount and self.totalExpected is not None and self.matchedCount is not None:
            self.missedCount = max(0, self.totalExpected - self.matchedCount)

        if self.totalExpected and self.totalExpected > 0:
            self.precisionScore = round(float(self.matchedCount) / float(self.totalExpected), 2)
            self.matchPercentage = round(self.precisionScore * 100.0, 2)

# Backward-compatible alias
ScenarioIndicatorVerificationReport = IndicatorVerificationReport