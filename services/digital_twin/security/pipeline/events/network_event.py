from enum import Enum
from typing import Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import threading

class NetworkEventTypeEnum(str, Enum):
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTPS_CONNECTION = "HTTPS_CONNECTION"
    SSH_CONNECTION = "SSH_CONNECTION"
    AUTHENTICATION_EVENT = "AUTHENTICATION_EVENT"
    PORT_ACTIVITY = "PORT_ACTIVITY"
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    IDS_ALERT = "IDS_ALERT"

class DetectionSourceEnum(str, Enum):
    PACKET_CAPTURE = "PACKET_CAPTURE"
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    SIMULATION = "SIMULATION"

class EventSeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventIdGenerator:
    """Thread-safe sequential event ID generator formatting as EVT-XXXXXX."""
    def __init__(self, prefix: str = "EVT-"):
        self._prefix = prefix
        self._counter = 0
        self._lock = threading.Lock()

    def generate(self) -> str:
        with self._lock:
            self._counter += 1
            return f"{self._prefix}{self._counter:06d}"

    def reset(self):
        with self._lock:
            self._counter = 0

event_id_generator = EventIdGenerator()

class NetworkEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: event_id_generator.generate())
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str
    destination: str
    sourcePort: Optional[int] = None
    destinationPort: Optional[int] = None
    protocol: str = "TCP"
    eventType: NetworkEventTypeEnum
    severity: Optional[EventSeverityEnum] = EventSeverityEnum.INFO
    detectionSource: DetectionSourceEnum
    bytes: int = Field(default=0, ge=0)
    packets: int = Field(default=1, ge=0)
    signature: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)