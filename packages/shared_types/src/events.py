from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid

class NetworkEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_ip: str
    destination_ip: str
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    detected_app: str = "UNKNOWN"
    packet_size: int = 64
    interface: str = "eth0"
    direction: str = "INTERNAL"
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"SEC-EVT-{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_device_id: Optional[str] = None
    destination_device_id: Optional[str] = None
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    event_type: str
    severity: str = "MEDIUM" # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    detection_source: str = "SIEM_CORRELATION_ENGINE"
    details: Dict[str, Any] = Field(default_factory=dict)