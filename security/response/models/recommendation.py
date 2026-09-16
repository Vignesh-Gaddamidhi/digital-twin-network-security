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
    alertId: str
    predictionId: str
    deviceId: str
    riskScore: float
    riskLevel: RiskLevelTier
    recommendedAction: ResponseActionType
    reason: str
    evidence: List[str] = Field(default_factory=list)
    confidence: float = 0.95
    priority: RecommendationPriorityEnum = RecommendationPriorityEnum.HIGH
    simulationRequired: bool = True
    status: RecommendationStatusEnum = RecommendationStatusEnum.PENDING
    targetLinkId: Optional[str] = None
    targetService: Optional[str] = None