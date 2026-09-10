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
    SSH = "SSH"
    PROTOCOL = "PROTOCOL"
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
    bytes: int = 0
    packets: int = 0
    application: Optional[str] = None
    severity: NormalizedSecuritySeverityEnum = NormalizedSecuritySeverityEnum.MEDIUM
    signature: str = "Generic Network Activity"
    category: Optional[str] = None
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    rawReference: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityCorrelationContext(BaseModel):
    correlationId: str = Field(default_factory=lambda: f"ctx-{uuid.uuid4().hex[:8]}")
    correlationKey: str
    firstSeen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastSeen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: Optional[str] = None
    destinationDevice: Optional[str] = None
    sourceIP: str
    destinationIP: str
    sourcePort: Optional[int] = None
    destinationPort: Optional[int] = None
    protocol: str
    sourcesInvolved: List[EventSourceEnum] = Field(default_factory=list)
    eventCount: int = 0
    totalBytes: int = 0
    totalPackets: int = 0
    hasAlert: bool = False
    highestSeverity: NormalizedSecuritySeverityEnum = NormalizedSecuritySeverityEnum.LOW
    associatedEventIds: List[str] = Field(default_factory=list)
    alertSignatures: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)