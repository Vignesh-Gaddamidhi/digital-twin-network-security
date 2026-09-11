from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class CanonicalDetectionSourceEnum(str, Enum):
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    SIMULATION = "SIMULATION"
    ANOMALY_DETECTOR = "ANOMALY_DETECTOR"

class CanonicalSeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class CanonicalProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"

class CanonicalEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:6].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    eventTimestamp: str
    processingTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str
    destination: str
    protocol: CanonicalProtocolEnum
    port: Optional[int] = None
    sourcePort: Optional[int] = None
    eventType: str
    severity: CanonicalSeverityEnum = CanonicalSeverityEnum.INFO
    detectionSource: CanonicalDetectionSourceEnum
    bytes: int = 0
    packets: int = 1
    signature: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class QuarantinedEventRecord(BaseModel):
    rawInput: Any
    rejectionReason: str
    attemptedSource: str
    quarantinedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())