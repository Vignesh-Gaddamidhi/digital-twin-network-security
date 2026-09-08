from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class AnomalyTypeEnum(str, Enum):
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    PORT_ANOMALY = "PORT_ANOMALY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"

class AnomalySeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AnomalyProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"anom-prof-{uuid.uuid4().hex[:6]}")
    name: str = "Volumetric-Traffic-Spike"
    anomalyType: AnomalyTypeEnum = AnomalyTypeEnum.TRAFFIC_SPIKE
    severity: AnomalySeverityEnum = AnomalySeverityEnum.MEDIUM
    durationSeconds: int = Field(default=30, ge=1, le=86400)
    affectedDevice: str = Field(..., min_length=1, description="Originating device injecting the anomaly")
    targetDevice: str = Field(..., min_length=1, description="Target endpoint absorbing the deviation")
    protocol: str = Field(default="TCP")
    intensity: float = Field(default=5.0, ge=1.1, le=100.0, description="Deviation multiplier relative to baseline")
    targetPort: Optional[int] = Field(default=None, ge=1, le=65535)
    baselineReferenceId: str = "normal-baseline-run-001"
    details: Dict[str, Any] = Field(default_factory=dict)

class AbnormalEventModel(BaseModel):
    eventId: str = Field(default_factory=lambda: f"abnormal-{uuid.uuid4().hex[:8]}")
    simulationId: str = "sim-001"
    deviceId: str = Field(..., min_length=1)
    targetDevice: str = Field(..., min_length=1)
    anomalyType: AnomalyTypeEnum
    severity: AnomalySeverityEnum
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    intensity: float = 1.0
    protocol: str = "TCP"
    destinationPort: Optional[int] = None
    metricObserved: str = "traffic_rate"
    baselineValue: float = 0.0
    abnormalValue: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)