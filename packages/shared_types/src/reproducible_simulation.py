from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class SimulationExecutionConfig(BaseModel):
    simulationId: str = Field(..., min_length=2, description="Globally unique simulation identifier (e.g. sim-001)")
    runId: str = Field(default_factory=lambda: f"run-{uuid.uuid4().hex[:8]}")
    scenarioId: str = Field(default="default-scenario", min_length=2)
    seed: int = Field(..., description="Deterministic pseudo-random seed (e.g. 12345)")
    duration: int = Field(default=300, description="Virtual duration in seconds")
    tickInterval: int = Field(default=1000, ge=1, le=60000, description="Tick step interval in milliseconds")
    speed: float = Field(default=1.0, description="Virtual clock playback multiplier")
    startTime: Optional[str] = None
    endTime: Optional[str] = None

    @field_validator("seed")
    @classmethod
    def validate_seed(cls, v: Any) -> int:
        if v is None or not isinstance(v, int):
            raise ValueError("Seed is required and must be an integer.")
        return v

    @field_validator("duration")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v <= 0:
            raise ValueError(f"Duration must be greater than 0 seconds. Got {v}")
        return v

    @field_validator("speed")
    @classmethod
    def validate_speed(cls, v: float) -> float:
        if v <= 0.0 or v > 100.0:
            raise ValueError(f"Speed multiplier must be positive and <= 100.0. Got {v}")
        return v

class ReproducibleSimulationEvent(BaseModel):
    sequenceNumber: int = Field(..., ge=1, description="Monotonically increasing sequence number")
    eventId: str = Field(default_factory=lambda: f"sim-evt-{uuid.uuid4().hex[:8]}")
    simulationId: str
    runId: str
    simTimeSeconds: float = Field(..., ge=0.0)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: str = Field(..., min_length=1)
    destinationDevice: str = Field(..., min_length=1)
    protocol: str = "TCP"
    sourcePort: int = Field(..., ge=1024, le=65535)
    destinationPort: int = Field(..., ge=1, le=65535)
    eventType: str = "CONNECTION"
    payloadSize: int = Field(default=0, ge=0)
    status: str = "SUCCESS"
    details: Dict[str, Any] = Field(default_factory=dict)

class SimulationRunComparisonResult(BaseModel):
    isIdentical: bool
    run1Id: str
    run2Id: str
    totalEventsRun1: int
    totalEventsRun2: int
    divergencePointSequence: Optional[int] = None
    divergenceReason: Optional[str] = None