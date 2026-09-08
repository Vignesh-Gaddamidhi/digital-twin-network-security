from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class SshSessionStateEnum(str, Enum):
    REQUESTED = "REQUESTED"
    AUTHENTICATING = "AUTHENTICATING"
    ESTABLISHED = "ESTABLISHED"
    IDLE = "IDLE"
    CLOSED = "CLOSED"
    FAILED = "FAILED"

class SshAuthMethodEnum(str, Enum):
    PUBLIC_KEY = "PUBLIC_KEY"
    PASSWORD = "PASSWORD"
    CERTIFICATE = "CERTIFICATE"

class SshTrafficProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"sshprof-{uuid.uuid4().hex[:6]}")
    name: str = "Admin-Bastion-Access"
    sourceAdmin: str = "admin-01"
    targetServers: List[str] = Field(default_factory=lambda: ["server-01", "web-01", "db-01"])
    authMethod: SshAuthMethodEnum = SshAuthMethodEnum.PUBLIC_KEY
    sessionDurationSecondsMean: int = Field(default=60, ge=1, le=86400)
    failureRate: float = Field(default=0.05, ge=0.0, le=1.0)
    sessionsCount: int = Field(default=3, ge=1)

class SshTransactionEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"ssh-evt-{uuid.uuid4().hex[:8]}")
    sessionId: str = Field(default_factory=lambda: f"ssh-sess-{uuid.uuid4().hex[:6]}")
    simulationId: str = "sim-001"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    protocol: str = "TCP"
    application: str = "SSH"
    sourceDevice: str = Field(..., min_length=1)
    destinationDevice: str = Field(..., min_length=1)
    sourcePort: int = Field(default=52000, ge=1, le=65535)
    destinationPort: int = Field(default=22, ge=1, le=65535)
    sessionState: SshSessionStateEnum = SshSessionStateEnum.REQUESTED
    username: str = "sysadmin"
    authMethod: SshAuthMethodEnum = SshAuthMethodEnum.PUBLIC_KEY
    bytes: int = Field(default=720, ge=0)
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("destinationPort")
    @classmethod
    def validate_ssh_port(cls, v: int) -> int:
        if v != 22 and not (1024 <= v <= 65535):
            raise ValueError(f"SSH port must be 22 or a valid custom high port. Got {v}")
        return v