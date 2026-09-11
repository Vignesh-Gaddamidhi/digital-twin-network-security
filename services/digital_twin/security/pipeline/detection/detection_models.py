from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class DetectionTypeEnum(str, Enum):
    BENIGN = "BENIGN"
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    PORT_ANOMALY = "PORT_ANOMALY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING_PATTERN = "BEACONING_PATTERN"
    AUTHENTICATION_ANOMALY = "AUTHENTICATION_ANOMALY"
    OUTBOUND_VOLUME_ANOMALY = "OUTBOUND_VOLUME_ANOMALY"
    IDS_SIGNATURE_MATCH = "IDS_SIGNATURE_MATCH"

class DetectionSeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ExplainableEvidence(BaseModel):
    metric: str
    observedValue: float
    expectedBaseline: float
    deviationScore: float
    reason: str

class DetectionResult(BaseModel):
    detectionId: str = Field(default_factory=lambda: f"DET-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    detected: bool = False
    detectionType: DetectionTypeEnum = DetectionTypeEnum.BENIGN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: DetectionSeverityEnum = DetectionSeverityEnum.INFO
    targetDevice: str
    sourceDevice: str
    evidence: List[ExplainableEvidence] = Field(default_factory=list)
    features: Dict[str, Any] = Field(default_factory=dict)
    detectionSource: str = "PIPELINE_DETECTOR"
    summary: str = "Traffic observed within normal baseline operational limits"