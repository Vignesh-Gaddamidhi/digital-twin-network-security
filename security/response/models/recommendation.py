from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

from security.response.models.action import ResponseActionType

class ResponseRecommendation(BaseModel):
    recommendationId: str = Field(default_factory=lambda: f"REC-{uuid.uuid4().hex[:8].upper()}")
    actionType: ResponseActionType
    targetDeviceId: str
    targetLinkId: Optional[str] = None
    targetService: Optional[str] = None
    confidenceScore: float
    riskScore: float
    reason: str
    triggeringAlertId: str
    triggeringPredictionId: str
    xaiExplanationSnippet: str
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())