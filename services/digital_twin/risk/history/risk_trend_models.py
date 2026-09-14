from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class RiskTrendDirection(str, Enum):
    INCREASING = "INCREASING"
    DECREASING = "DECREASING"
    STABLE = "STABLE"
    VOLATILE = "VOLATILE"
    UNKNOWN = "UNKNOWN"

class RiskEventType(str, Enum):
    RISK_LEVEL_INCREASED = "RISK_LEVEL_INCREASED"
    RISK_LEVEL_DECREASED = "RISK_LEVEL_DECREASED"
    HIGH_RISK_REACHED = "HIGH_RISK_REACHED"
    CRITICAL_RISK_REACHED = "CRITICAL_RISK_REACHED"
    RISK_SCORE_SPIKE = "RISK_SCORE_SPIKE"
    RISK_STABILIZED = "RISK_STABILIZED"

class RiskHistoryObservation(BaseModel):
    observationId: str = Field(default_factory=lambda: f"ROBS-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    riskScore: float
    riskLevel: RiskLevelTier
    predictionId: str
    explanationId: Optional[str] = None

class RiskTransitionEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"REVT-{uuid.uuid4().hex[:8].upper()}")
    deviceId: str
    eventType: RiskEventType
    previousRiskLevel: Optional[RiskLevelTier] = None
    currentRiskLevel: RiskLevelTier
    previousScore: Optional[float] = None
    currentScore: float
    scoreDelta: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rationale: str
    cooldownActive: bool = False

class DeviceContinuousRiskState(BaseModel):
    deviceId: str
    currentRiskScore: float
    currentRiskLevel: RiskLevelTier
    riskTrend: RiskTrendDirection
    consecutiveObservations: int = 1
    lastAssessmentAt: str
    history: List[RiskHistoryObservation] = Field(default_factory=list)

class NetworkRiskAggregation(BaseModel):
    aggregationId: str = Field(default_factory=lambda: f"NAGG-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    strategy: str = "MAX"  # MAX, WEIGHTED_AVERAGE, TOP_N
    networkRiskScore: float
    networkRiskLevel: RiskLevelTier
    highestRiskDevice: str
    monitoredDeviceCount: int
    criticalDeviceCount: int
    highDeviceCount: int
    deviceScores: Dict[str, float]