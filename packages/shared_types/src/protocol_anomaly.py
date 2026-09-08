from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ProtocolWindowPhaseEnum(str, Enum):
    NORMAL_PERIOD = "NORMAL_PERIOD"
    ABNORMAL_PERIOD = "ABNORMAL_PERIOD"
    RECOVERY_PERIOD = "RECOVERY_PERIOD"

class ProtocolDistributionProfile(BaseModel):
    name: str = "Corporate-Protocol-Weights"
    weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "HTTPS": 0.60,
            "DNS": 0.20,
            "HTTP": 0.10,
            "SSH": 0.05,
            "ICMP": 0.05
        }
    )

class WindowProtocolStats(BaseModel):
    windowPhase: ProtocolWindowPhaseEnum
    durationSeconds: int
    totalPackets: int
    counts: Dict[str, int]
    percentages: Dict[str, float]
    startTime: str
    endTime: str

class ProtocolAnomalyEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"protoanom-{uuid.uuid4().hex[:8]}")
    simulationId: str = "sim-proto-01"
    anomalyType: str = "PROTOCOL_ANOMALY"
    timeWindow: ProtocolWindowPhaseEnum
    sourceDevice: str
    destinationDevice: str
    expectedDominantProtocol: str = "HTTPS"
    observedDominantProtocol: str = "ICMP"
    expectedPercentage: float = 5.0
    observedPercentage: float = 65.0
    deviation: float = 0.60
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)

class ProtocolAnomalyRunResult(BaseModel):
    runId: str = Field(default_factory=lambda: f"run-protoanom-{uuid.uuid4().hex[:8]}")
    totalDurationSeconds: int
    totalEvents: int
    normalWindowStats: WindowProtocolStats
    abnormalWindowStats: WindowProtocolStats
    recoveryWindowStats: WindowProtocolStats
    detectedAnomalies: List[ProtocolAnomalyEvent] = Field(default_factory=list)