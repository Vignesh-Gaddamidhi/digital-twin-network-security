from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class SessionStateEnum(str, Enum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    FAILED = "FAILED"

class DeviceNetworkMetricsModel(BaseModel):
    networkUtilisation: float = Field(default=0.0, ge=0.0, le=100.0, description="Line utilization percentage (0-100%)")
    bytesSent: int = Field(default=0, ge=0)
    bytesReceived: int = Field(default=0, ge=0)
    packetsSent: int = Field(default=0, ge=0)
    packetsReceived: int = Field(default=0, ge=0)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ActiveConnectionSessionModel(BaseModel):
    id: str = Field(default_factory=lambda: f"conn-{uuid.uuid4().hex[:6]}")
    source: str = Field(..., min_length=1, description="Originating client device ID")
    destination: str = Field(..., min_length=1, description="Target host device ID")
    protocol: str = Field(default="TCP")
    sourcePort: int = Field(..., ge=1, le=65535)
    destinationPort: int = Field(..., ge=1, le=65535)
    status: SessionStateEnum = Field(default=SessionStateEnum.ACTIVE)
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastSeen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in ("TCP", "UDP", "ICMP", "IP"):
            raise ValueError(f"Invalid protocol: '{v}'. Must be TCP, UDP, ICMP, or IP.")
        return v_upper

class DeviceConnectionStatsModel(BaseModel):
    deviceId: str
    active: int = 0
    closed: int = 0
    failed: int = 0
    total: int = 0