from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.topology_models import TopologyNodeState
from frontend.topology.link_3d_models import TrafficProtocolType, TrafficFlowDirectionEnum

class RealtimeEventType(str, Enum):
    DEVICE_STATE_UPDATE = "DEVICE_STATE_UPDATE"
    CPU_UPDATE = "CPU_UPDATE"
    MEMORY_UPDATE = "MEMORY_UPDATE"
    TRAFFIC_UPDATE = "TRAFFIC_UPDATE"
    CONNECTION_UPDATE = "CONNECTION_UPDATE"
    THREAT_UPDATE = "THREAT_UPDATE"
    ALERT_UPDATE = "ALERT_UPDATE"
    PREDICTION_UPDATE = "PREDICTION_UPDATE"
    RISK_UPDATE = "RISK_UPDATE"
    ATTACK_PATH_UPDATE = "ATTACK_PATH_UPDATE"
    SIMULATION_STATUS_UPDATE = "SIMULATION_STATUS_UPDATE"
    EARLY_WARNING_UPDATE = "EARLY_WARNING_UPDATE"
    TWIN_STATE_UPDATE = "TWIN_STATE_UPDATE"
    HEARTBEAT = "HEARTBEAT"
    ERROR = "ERROR"

class RealtimeConnectionState(str, Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    RECONNECTING = "RECONNECTING"

class DataFreshnessState(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"

class BackendHealthState(str, Enum):
    HEALTHY = "HEALTHY"
    BACKEND_ERROR = "BACKEND_ERROR"
    UNAVAILABLE = "UNAVAILABLE"

# ==================== INCREMENTAL PAYLOAD CONTRACTS ====================

class DeviceStatePayload(BaseModel):
    deviceId: str
    previousState: TopologyNodeState
    newState: TopologyNodeState
    reason: str
    quarantineEnforced: bool = False

class CpuTelemetryPayload(BaseModel):
    deviceId: str
    cpuUtilizationPct: float
    coreLoads: List[float] = Field(default_factory=list)
    temperatureCelsius: float = 48.0

class MemoryTelemetryPayload(BaseModel):
    deviceId: str
    memoryUsedMb: float
    memoryTotalMb: float = 16384.0
    memoryUtilizationPct: float

class TrafficTelemetryPayload(BaseModel):
    linkId: str
    sourceDeviceId: str
    destinationDeviceId: str
    protocol: TrafficProtocolType
    packetsPerSecond: float
    bytesPerSecond: float
    activeConnections: int

class ConnectionStatePayload(BaseModel):
    connectionId: str
    linkId: str
    status: str  # ACTIVE, BLOCKED, DEGRADED
    isReachable: bool
    packetDropRatePct: float = 0.0

class ThreatTelemetryPayload(BaseModel):
    threatId: str
    sourceDeviceId: str
    targetDeviceId: str
    eventType: str
    severity: RiskLevelTier
    confidenceScore: float
    detectionSource: str

class AlertTelemetryPayload(BaseModel):
    alertId: str
    severity: RiskLevelTier
    sourceDevice: str
    destinationDevice: str
    eventType: str
    status: str  # NEW, INVESTIGATING, RESOLVED
    riskScore: float

class PredictionTelemetryPayload(BaseModel):
    targetDeviceId: str
    currentThreatProbability: float
    futureThreatProbability: float
    predictedCategory: str
    confidenceScore: float
    topFeatures: List[str] = Field(default_factory=list)

class RiskTelemetryPayload(BaseModel):
    targetDeviceId: str
    compositeRiskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    assetCriticality: str
    vulnerabilityFactor: float
    attackImpact: float

class AttackPathTelemetryPayload(BaseModel):
    pathId: str
    sourceDevice: str
    targetDevice: str
    nodeSequence: List[str]
    hopCount: int
    riskScore: float
    riskLevel: RiskLevelTier
    reachability: str
    isCompromisedChain: bool = False

class SimulationStatusPayload(BaseModel):
    simulationId: str
    scenario: str
    executionState: str  # IDLE, RUNNING, PAUSED, STOPPED
    currentStage: str     # NORMAL, EARLY_INDICATORS, ESCALATION, IMPACT, RECOVERY
    elapsedSeconds: int
    totalDurationSeconds: int
    progressPct: float

class EarlyWarningPayload(BaseModel):
    targetDeviceId: str
    leadTimeSeconds: int
    futureThreatProbability: float
    warningState: str  # NO_WARNING, WATCH, EARLY_WARNING, HIGH_CONFIDENCE_WARNING, IMPACT_STAGE

class HeartbeatPayload(BaseModel):
    activeConnectionsCount: int
    totalEventsEmitted: int
    serverTimeUtc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ErrorPayload(BaseModel):
    errorCode: str
    errorMessage: str
    subsystem: str
    recoverable: bool = True

# ==================== UNIFIED REALTIME EVENT ENVELOPE ====================

class RealtimeEventEnvelope(BaseModel):
    eventId: str = Field(default_factory=lambda: f"RTE-{uuid.uuid4().hex[:8].upper()}")
    eventType: RealtimeEventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    receivedTimestamp: Optional[str] = None
    processedTimestamp: Optional[str] = None
    sequenceNumber: int
    simulationId: Optional[str] = None
    source: str = "CANONICAL_DIGITAL_TWIN"
    deviceId: Optional[str] = None
    version: str = "1.0"
    payload: Dict[str, Any]
    metadata: Dict[str, Any] = Field(default_factory=dict)

# ==================== FULL MONOLITHIC TWIN SNAPSHOT ====================

class TwinStateSnapshot(BaseModel):
    snapshotId: str = Field(default_factory=lambda: f"SNAP-{uuid.uuid4().hex[:8].upper()}")
    sequenceNumber: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    connectionState: RealtimeConnectionState = RealtimeConnectionState.CONNECTED
    freshness: DataFreshnessState = DataFreshnessState.FRESH
    backendHealth: BackendHealthState = BackendHealthState.HEALTHY
    devices: List[Dict[str, Any]] = Field(default_factory=list)
    connections: List[Dict[str, Any]] = Field(default_factory=list)
    topology: Dict[str, Any] = Field(default_factory=dict)
    traffic: Dict[str, Any] = Field(default_factory=dict)
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    predictions: Dict[str, Any] = Field(default_factory=dict)
    risks: Dict[str, Any] = Field(default_factory=dict)
    attackPaths: List[Dict[str, Any]] = Field(default_factory=list)
    simulation: Dict[str, Any] = Field(default_factory=dict)
    earlyWarnings: Dict[str, Any] = Field(default_factory=dict)