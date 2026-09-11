from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class RiskLevelEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ContributingFactor(BaseModel):
    category: str  # LIKELIHOOD | IMPACT | ASSET | VULNERABILITY
    factor: str
    weightEffect: str
    description: str

class RiskAssessment(BaseModel):
    riskId: str = Field(default_factory=lambda: f"RSK-{uuid.uuid4().hex[:8].upper()}")
    detectionId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    targetDevice: str
    sourceDevice: str
    score: float = Field(ge=0.0, le=100.0)
    level: RiskLevelEnum
    likelihood: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=10.0)
    contributingFactors: List[ContributingFactor] = Field(default_factory=list)
    explanation: str
    metadata: Dict[str, Any] = Field(default_factory=dict)