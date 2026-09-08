from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class SimulationStateEnum(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"

class SimulationEventTypeEnum(str, Enum):
    CONNECTION = "CONNECTION"
    PACKET = "PACKET"
    SERVICE_REQUEST = "SERVICE_REQUEST"
    ANOMALY = "ANOMALY"
    CONTROL = "CONTROL"

class TrafficProfileModel(BaseModel):
    profileId: str = Field(default_factory=lambda: f"prof-{uuid.uuid4().hex[:6]}")
    name: str = "Standard-HTTP-Traffic"
    protocol: str = "TCP"
    destinationPort: int = 443
    ratePerSecond: float = Field(default=1.0, ge=0.1, le=1000.0)
    payloadBytesMean: int = Field(default=1024, ge=64)

class ScenarioModel(BaseModel):
    scenarioId: str = Field(..., min_length=2, description="Unique identifier (e.g., normal-office-001)")
    name: str = Field(..., min_length=2)
    duration: int = Field(default=300, ge=1, le=86400, description="Virtual duration in seconds")
    seed: int = Field(default=12345, description="Random seed for deterministic replay")
    devices: List[str] = Field(default_factory=list, description="IDs of devices included in scenario")
    trafficProfiles: List[TrafficProfileModel] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SimulationEventModel(BaseModel):
    eventId: str = Field(default_factory=lambda: f"sim-evt-{uuid.uuid4().hex[:8]}")
    scenarioId: str
    simTimeSeconds: float = Field(..., ge=0.0)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: str = Field(..., min_length=1)
    destinationDevice: str = Field(..., min_length=1)
    protocol: str = "TCP"
    sourcePort: int = Field(..., ge=1024, le=65535)
    destinationPort: int = Field(..., ge=1, le=65535)
    eventType: SimulationEventTypeEnum = SimulationEventTypeEnum.CONNECTION
    payloadSize: int = Field(default=0, ge=0)
    status: str = "SUCCESS"
    details: Dict[str, Any] = Field(default_factory=dict)

class SimulationStatusSnapshotModel(BaseModel):
    scenarioId: Optional[str] = None
    state: SimulationStateEnum
    simCurrentTimeSeconds: float
    targetDuration: int
    eventsGeneratedCount: int
    isClockRunning: bool
    startedAt: Optional[str] = None
    lastTickAt: Optional[str] = None