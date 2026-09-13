from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class RollingFeatureSet(BaseModel):
    windowSize: int
    mean: float
    std: float
    minVal: float
    maxVal: float
    median: float

class TemporalDynamicMetrics(BaseModel):
    rateOfChange: float
    percentageChange: float
    velocity: float
    acceleration: float
    trendDirection: str  # INCREASING, DECREASING, STABLE

class TimeSeriesObservation(BaseModel):
    observationId: str = Field(default_factory=lambda: f"TS-OBS-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    timeStepIndex: int = 0
    intervalSeconds: float = 5.0
    deviceId: str = "SERVER-01"
    source: str = "CLIENT-01"
    destination: str = "SERVER-01"

    # Core Telemetry Features
    packetRate: float = 0.0
    bytesVal: float = 0.0
    bytesPerSecond: float = 0.0
    connectionFrequency: float = 0.0
    portDistribution: Dict[str, float] = Field(default_factory=dict)
    flowDuration: float = 0.0
    protocolDistribution: Dict[str, float] = Field(default_factory=dict)
    failedConnections: float = 0.0
    dnsFrequency: float = 0.0
    destinationDiversity: float = 0.0

    # Lag Vectors (t-1, t-2, t-3)
    lagFeatures: Dict[str, List[float]] = Field(default_factory=dict)

    # Rolling Statistical Windows
    rollingFeatures: Dict[str, RollingFeatureSet] = Field(default_factory=dict)

    # Dynamics (First & Second Derivatives)
    dynamics: Dict[str, TemporalDynamicMetrics] = Field(default_factory=dict)

    # Target & Ground Truth Context
    label: str = "NORMAL"
    stage: str = "BASELINE"  # BASELINE, PRE_IMPACT, IMPACT
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_flat_feature_vector(self) -> List[float]:
        """Produces ordered numeric vector suitable for temporal sequential input."""
        vec = [
            self.packetRate,
            self.bytesVal,
            self.bytesPerSecond,
            self.connectionFrequency,
            self.flowDuration,
            self.failedConnections,
            self.dnsFrequency,
            self.destinationDiversity
        ]
        # Append primary dynamic metrics for packetRate and bytesPerSecond
        for key in ["packetRate", "bytesPerSecond"]:
            if key in self.dynamics:
                d = self.dynamics[key]
                vec.extend([d.rateOfChange, d.percentageChange, d.velocity, d.acceleration])
            else:
                vec.extend([0.0, 0.0, 0.0, 0.0])
        return [round(float(v), 4) for v in vec]