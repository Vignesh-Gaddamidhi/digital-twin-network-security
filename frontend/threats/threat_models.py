from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class DetectionSourceEnum(str, Enum):
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    SIMULATION = "SIMULATION"
    ANOMALY_DETECTOR = "ANOMALY_DETECTOR"
    ML = "ML"
    TIME_SERIES = "TIME_SERIES"

class ThreatTimelineItem(BaseModel):
    eventId: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str
    eventType: str
    sourceDevice: str
    destinationDevice: str
    protocol: str = "TCP"
    destinationPort: int = 80
    severity: RiskLevelTier
    detectionSource: DetectionSourceEnum
    confidence: float = 0.90
    riskScore: float = 50.0
    summary: str = ""

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_format(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Timestamp cannot be null or empty.")
        try:
            _ = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(f"Invalid ISO-8601 timestamp format: {v}") from e
        return v

class ThreatFilterCriteria(BaseModel):
    severity: Optional[RiskLevelTier] = None
    detectionSource: Optional[DetectionSourceEnum] = None
    eventType: Optional[str] = None
    device: Optional[str] = None
    minRiskScore: Optional[float] = None
    startTime: Optional[str] = None
    endTime: Optional[str] = None

class UnifiedIncidentDrillDown(BaseModel):
    drillDownId: str = Field(default_factory=lambda: f"INCD-{uuid.uuid4().hex[:8].upper()}")
    event: ThreatTimelineItem
    extractedFeatures: Dict[str, float] = Field(default_factory=dict)
    detectionDetails: Dict[str, Any] = Field(default_factory=dict)
    riskAssessment: Dict[str, Any] = Field(default_factory=dict)
    predictionAttribution: Dict[str, Any] = Field(default_factory=dict)
    xaiExplanation: str
    recommendedContainment: str