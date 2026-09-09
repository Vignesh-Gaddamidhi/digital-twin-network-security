from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class EventSourceEnum(str, Enum):
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    SIMULATION = "SIMULATION"
    HYBRID = "HYBRID"

class SecurityEventTypeEnum(str, Enum):
    ALERT = "ALERT"
    FLOW = "FLOW"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"
    ANOMALY = "ANOMALY"

class NormalizedSecuritySeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class NormalizedSecurityEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"sec-evt-{uuid.uuid4().hex[:8]}")
    source: EventSourceEnum
    eventType: SecurityEventTypeEnum
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: Optional[str] = None
    destinationDevice: Optional[str] = None
    sourceIP: str
    destinationIP: str
    sourcePort: Optional[int] = None
    destinationPort: Optional[int] = None
    protocol: str = "TCP"
    severity: NormalizedSecuritySeverityEnum = NormalizedSecuritySeverityEnum.MEDIUM
    signature: str = "Generic Network Activity"
    category: Optional[str] = None
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    rawReference: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)