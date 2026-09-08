from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ConnectionLifecycleStateEnum(str, Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLOSED = "CLOSED"
    FAILED = "FAILED"

class ConnectionAnomalyPatternEnum(str, Enum):
    BALANCED_NORMAL = "BALANCED_NORMAL"
    HIGH_NEW_HIGH_FAILED = "HIGH_NEW_HIGH_FAILED"  # Many NEW, Few ESTABLISHED, Many FAILED
    RAPID_EXHAUSTION = "RAPID_EXHAUSTION"          # Rapid escalation to target capacity

class ConnectionAnomalyProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"connanom-{uuid.uuid4().hex[:6]}")
    name: str = "Unusual-Connection-Bursts"
    affectedDevice: str = "client-01"
    targetDevice: str = "web-01"
    targetPort: int = Field(default=443, ge=1, le=65535)
    protocol: str = "TCP"
    normalConnectionRate: int = Field(default=5, ge=1, description="Normal active connections")
    abnormalConnectionRate: int = Field(default=100, ge=10, description="Escalated active connections target")
    durationSeconds: int = Field(default=15, ge=1, le=86400)
    lifecyclePattern: ConnectionAnomalyPatternEnum = ConnectionAnomalyPatternEnum.HIGH_NEW_HIGH_FAILED

class LifecycleStateBreakdown(BaseModel):
    newCount: int = 0
    establishedCount: int = 0
    closedCount: int = 0
    failedCount: int = 0

class ConnectionAnomalyRunResult(BaseModel):
    runId: str = Field(default_factory=lambda: f"run-connanom-{uuid.uuid4().hex[:8]}")
    profileId: str
    targetDevice: str
    protocol: str
    destinationPort: int
    classification: str = "UNUSUAL_CONNECTION_BEHAVIOUR"
    baselineActiveConnections: int
    peakActiveConnections: int
    lifecycleSummary: LifecycleStateBreakdown
    connectionLevelsObserved: List[int] = Field(default_factory=list) # e.g. [5, 10, 20, 50, 100]
    totalTransactions: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())