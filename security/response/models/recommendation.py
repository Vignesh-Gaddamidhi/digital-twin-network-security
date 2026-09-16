from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
import itertools

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from security.response.models.action import ResponseActionType

_recommendation_id_counter = itertools.count(1)

def generate_canonical_recommendation_id() -> str:
    now = datetime.now(timezone.utc)
    count = next(_recommendation_id_counter)
    return f"REC-{now.strftime('%Y%m%d')}-{count:06d}"

class RecommendationStatusEnum(str, Enum):
    PENDING = "PENDING"
    APPROVED_FOR_SIMULATION = "APPROVED_FOR_SIMULATION"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"

class RecommendationPriorityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ResponseRecommendation(BaseModel):
    """Canonical recommendation object mapping security intelligence to simulated playbooks."""
    recommendationId: str = Field(default_factory=generate_canonical_recommendation_id)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    alertId: str = ""
    predictionId: str = ""
    deviceId: str = ""
    targetDeviceId: str = ""
    riskScore: float = 0.0
    riskLevel: RiskLevelTier = RiskLevelTier.HIGH
    recommendedAction: ResponseActionType = ResponseActionType.ISOLATE_DEVICE
    actionType: ResponseActionType = ResponseActionType.ISOLATE_DEVICE
    reason: str = ""
    evidence: List[str] = Field(default_factory=list)
    confidence: float = 0.95
    confidenceScore: float = 0.95
    priority: RecommendationPriorityEnum = RecommendationPriorityEnum.HIGH
    simulationRequired: bool = True
    status: RecommendationStatusEnum = RecommendationStatusEnum.PENDING
    targetLinkId: Optional[str] = None
    targetService: Optional[str] = None
    triggeringAlertId: str = ""
    triggeringPredictionId: str = ""
    xaiExplanationSnippet: str = ""

    def __init__(self, **data):
        if "actionType" in data and "recommendedAction" not in data:
            data["recommendedAction"] = data["actionType"]
        elif "recommendedAction" in data and "actionType" not in data:
            data["actionType"] = data["recommendedAction"]
            
        if "targetDeviceId" in data and "deviceId" not in data:
            data["deviceId"] = data["targetDeviceId"]
        elif "deviceId" in data and "targetDeviceId" not in data:
            data["targetDeviceId"] = data["deviceId"]
            
        if "triggeringAlertId" in data and "alertId" not in data:
            data["alertId"] = data["triggeringAlertId"]
        elif "alertId" in data and "triggeringAlertId" not in data:
            data["triggeringAlertId"] = data["alertId"]
            
        if "triggeringPredictionId" in data and "predictionId" not in data:
            data["predictionId"] = data["triggeringPredictionId"]
        elif "predictionId" in data and "triggeringPredictionId" not in data:
            data["triggeringPredictionId"] = data["predictionId"]
            
        if "confidenceScore" in data and "confidence" not in data:
            data["confidence"] = data["confidenceScore"]
            
        super().__init__(**data)