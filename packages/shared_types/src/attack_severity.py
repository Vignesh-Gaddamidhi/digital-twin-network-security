from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class SeverityLevelEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskLevelEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AssetCriticalityEnum(str, Enum):
    LOW = "LOW"           # Guest workstations, test endpoints
    MEDIUM = "MEDIUM"     # Standard workstations, internal proxies
    HIGH = "HIGH"         # Core application web servers, directory servers
    CRITICAL = "CRITICAL" # Production databases, payment vaults, domain controllers

class ScenarioClassificationResult(BaseModel):
    scenarioId: str
    category: str
    initialSeverity: SeverityLevelEnum
    targetDevice: str
    targetCriticality: AssetCriticalityEnum
    isExfiltrationVector: bool = False
    isLateralMovementVector: bool = False
    description: str

class RiskAssessmentReport(BaseModel):
    assessmentId: str = Field(default_factory=lambda: f"risk-{uuid.uuid4().hex[:8]}")
    scenarioId: str
    targetDevice: str
    baseSeverity: SeverityLevelEnum
    likelihoodScore: float = Field(..., ge=0.0, le=1.0, description="Probability of execution success (0.0 to 1.0)")
    impactScore: float = Field(..., ge=0.0, le=10.0, description="Potential damage to operational environment (0.0 to 10.0)")
    riskScore: float = Field(..., ge=0.0, le=100.0, description="Composite Risk Score = Likelihood * Impact * 10")
    riskLevel: RiskLevelEnum
    mitigatingFactors: List[str] = Field(default_factory=list)
    aggravatingFactors: List[str] = Field(default_factory=list)
    evaluatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())