from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ConnectionStateEnum(str, Enum):
    CONNECTED = "CONNECTED"
    CONNECTING = "CONNECTING"
    DISCONNECTED = "DISCONNECTED"
    RECONNECTING = "RECONNECTING"

class SubsystemStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    SYNCED = "SYNCED"
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    STALE = "STALE"

class SubsystemHealthPanel(BaseModel):
    backendConnection: ConnectionStateEnum = ConnectionStateEnum.CONNECTED
    digitalTwinSync: SubsystemStatusEnum = SubsystemStatusEnum.SYNCED
    telemetryStream: SubsystemStatusEnum = SubsystemStatusEnum.ACTIVE
    mlInference: SubsystemStatusEnum = SubsystemStatusEnum.AVAILABLE
    simulationEngine: SubsystemStatusEnum = SubsystemStatusEnum.ACTIVE
    lastHeartbeat: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dataAgeSeconds: float = 0.5
    isStale: bool = False

class PipelineObservabilityMetrics(BaseModel):
    eventsPerSecond: float = 24.5
    processingLatencyMs: float = 4.2
    predictionLatencyMs: float = 2.1
    apiLatencyMs: float = 8.5
    failedEventsCount: int = 0
    droppedEventsCount: int = 0
    pipelineStatus: str = "HEALTHY"

class GlobalSearchResultItem(BaseModel):
    category: str  # DEVICE, IP, EVENT, ALERT, ATTACK_PATH, PREDICTION, SIMULATION
    identifier: str
    title: str
    description: str
    deepLinkRoute: str
    riskScore: Optional[float] = None
    severity: Optional[str] = None

class UnifiedGlobalSearchResponse(BaseModel):
    query: str
    totalMatches: int
    results: List[GlobalSearchResultItem] = Field(default_factory=list)

class RealtimeDashboardFrame(BaseModel):
    frameId: str = Field(default_factory=lambda: f"FRM-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    health: SubsystemHealthPanel
    observability: PipelineObservabilityMetrics
    kpiSummary: Dict[str, Any]
    activeAlertsCount: int
    currentPacketsPerSec: float
    networkRiskScore: float