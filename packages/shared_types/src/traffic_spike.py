from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class SpikePhaseEnum(str, Enum):
    BASELINE = "BASELINE"
    RAMP_UP = "RAMP_UP"
    PEAK = "PEAK"
    RAMP_DOWN = "RAMP_DOWN"
    RECOVERY = "RECOVERY"

class TrafficSpikeProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"spike-prof-{uuid.uuid4().hex[:6]}")
    name: str = "Volumetric-Spike-Web"
    affectedDevice: str = "client-01"
    targetDevice: str = "web-01"
    targetPort: int = 443
    baselineRate: float = Field(default=100.0, ge=1.0, description="Events per minute in baseline")
    spikeRate: float = Field(default=800.0, ge=10.0, description="Events per minute during peak spike")
    baselineDuration: int = Field(default=3, ge=1, description="Seconds in baseline before ramp-up")
    rampUpTime: int = Field(default=2, ge=1, description="Seconds taken to reach peak")
    spikeDuration: int = Field(default=10, ge=1, description="Seconds sustained at peak spike")
    rampDownTime: int = Field(default=2, ge=1, description="Seconds taken to return to baseline")
    recoveryDuration: int = Field(default=3, ge=1, description="Seconds observed after returning to baseline")

class SpikeTickTelemetry(BaseModel):
    simTimeSeconds: float
    phase: SpikePhaseEnum
    targetDevice: str
    currentRatePerMin: float
    eventsInTick: int
    bytesInTick: int
    simulatedNetworkUtilisation: float
    simulatedActiveConnections: int
    simulatedCpuLoad: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class TrafficSpikeRunResult(BaseModel):
    runId: str = Field(default_factory=lambda: f"run-spike-{uuid.uuid4().hex[:8]}")
    profileId: str
    targetDevice: str
    totalDurationSeconds: int
    totalEventsEmitted: int
    totalBytesTransferred: int
    peakRatePerMinObserved: float
    maxNetworkUtilisation: float
    maxActiveConnections: int
    maxCpuLoad: float
    telemetryTimeline: List[SpikeTickTelemetry] = Field(default_factory=list)