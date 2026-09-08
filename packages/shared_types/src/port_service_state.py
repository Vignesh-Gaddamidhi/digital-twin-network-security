from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class PortStateEnum(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"

class ServiceDaemonStateEnum(str, Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

class TrackedPortModel(BaseModel):
    port: int = Field(..., ge=1, le=65535, description="Port number (1-65535)")
    protocol: str = Field(default="TCP", description="TCP, UDP")
    service: str = Field(default="unknown", description="Associated service protocol name")
    state: PortStateEnum = Field(default=PortStateEnum.OPEN)
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("protocol")
    @classmethod
    def validate_proto(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in ("TCP", "UDP"):
            raise ValueError(f"Invalid protocol: '{v}'. Must be TCP or UDP.")
        return v_upper

class TrackedServiceModel(BaseModel):
    name: str = Field(..., min_length=1, description="Service daemon or process name")
    protocol: str = Field(default="TCP")
    port: int = Field(..., ge=1, le=65535)
    status: ServiceDaemonStateEnum = Field(default=ServiceDaemonStateEnum.RUNNING)
    version: Optional[str] = Field(default=None, description="Software version string")
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("protocol")
    @classmethod
    def validate_proto(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in ("TCP", "UDP"):
            raise ValueError(f"Invalid protocol: '{v}'. Must be TCP or UDP.")
        return v_upper

class DevicePortServiceSnapshotModel(BaseModel):
    deviceId: str
    ports: List[TrackedPortModel] = Field(default_factory=list)
    services: List[TrackedServiceModel] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class PortServiceAuditEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"psev-{uuid.uuid4().hex[:8]}")
    deviceId: str
    eventType: str  # PORT_OPENED, PORT_CLOSED, PORT_STATE_CHANGED, SERVICE_STARTED, SERVICE_STOPPED, SERVICE_FAILED
    target: str     # Port number or Service name
    previousState: Optional[str] = None
    newState: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reason: str = "Runtime event"