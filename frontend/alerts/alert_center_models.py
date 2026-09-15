from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.threats.threat_models import DetectionSourceEnum

class AlertStatusEnum(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"

class SecurityAlertItem(BaseModel):
    alertId: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:6].upper()}")
    timestamp: str
    severity: RiskLevelTier
    sourceDevice: str
    destinationDevice: str
    eventType: str
    detectionSource: DetectionSourceEnum
    confidence: float
    riskScore: float
    status: AlertStatusEnum = AlertStatusEnum.NEW
    correlatedCampaignId: Optional[str] = None
    summary: str = ""

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Alert timestamp cannot be empty.")
        try:
            _ = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(f"Invalid timestamp format: {v}") from e
        return v

class CorrelatedIncidentCampaign(BaseModel):
    campaignId: str = Field(default_factory=lambda: f"CAMP-{uuid.uuid4().hex[:6].upper()}")
    campaignName: str
    involvedAlertIds: List[str]
    participatingDevices: List[str]
    rootCauseCategory: str
    maxSeverity: RiskLevelTier
    aggregateRiskScore: float
    timelineSpan: str
    narrative: str

class AlertFilterCriteria(BaseModel):
    severity: Optional[RiskLevelTier] = None
    status: Optional[AlertStatusEnum] = None
    device: Optional[str] = None
    detectionSource: Optional[DetectionSourceEnum] = None
    eventType: Optional[str] = None
    minRiskScore: Optional[float] = None
    timeRange: Optional[str] = None

class AlertCounterSummary(BaseModel):
    newAlerts: int = 0
    investigatingAlerts: int = 0
    highSeverityAlerts: int = 0
    criticalSeverityAlerts: int = 0
    totalActive: int = 0

class EightTierAlertDrillDown(BaseModel):
    alert: SecurityAlertItem
    eventContext: Dict[str, Any]
    featureVector: Dict[str, float]
    detectionDetails: Dict[str, Any]
    mlPrediction: Dict[str, Any]
    xaiAttribution: Dict[str, Any]
    riskBreakdown: Dict[str, Any]
    attackPathTrajectory: Dict[str, Any]
    affectedDeviceSummary: Dict[str, Any]