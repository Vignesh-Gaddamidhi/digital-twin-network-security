from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class RepeatedConnectionProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"repconn-{uuid.uuid4().hex[:6]}")
    name: str = "Rapid-Reconnect-Loop"
    sourceDevice: str = "client-01"
    destinationDevice: str = "server-01"
    destinationPort: int = 22
    protocol: str = "TCP"
    attemptCount: int = Field(default=100, ge=5, le=10000)
    windowSeconds: int = Field(default=10, ge=1, le=3600)
    expectedSuccessRate: float = Field(default=0.03, ge=0.0, le=1.0) # 3% success, 97% fail

class RepeatedConnectionEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"rep-evt-{uuid.uuid4().hex[:8]}")
    simulationId: str = "sim-rep-01"
    anomalyType: str = "REPEATED_CONNECTION"
    sourceDevice: str
    destinationDevice: str
    destinationPort: int
    attemptCount: int
    successfulCount: int
    failedCount: int
    windowSeconds: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)