from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class AuthEventTypeEnum(str, Enum):
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"

class SimulatedAuthEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"auth-{uuid.uuid4().hex[:8]}")
    scenarioId: str = "SCN-BRUTEFORCE-001"
    sourceDevice: str
    targetDevice: str
    service: str = "SSH"  # SSH, HTTP, RDP
    port: int = 22
    username: str
    eventType: AuthEventTypeEnum
    failureReason: Optional[str] = None
    attemptNumber: int = 1
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)