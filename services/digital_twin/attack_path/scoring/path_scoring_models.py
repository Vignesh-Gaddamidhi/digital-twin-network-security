from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class VulnerabilityRelevanceEnum(str, Enum):
    RELEVANT = "RELEVANT"
    POSSIBLY_RELEVANT = "POSSIBLY_RELEVANT"
    NOT_RELEVANT = "NOT_RELEVANT"
    UNKNOWN = "UNKNOWN"

class VulnerabilityRelevanceAssessment(BaseModel):
    vulnerabilityId: str
    nodeId: str
    relevance: VulnerabilityRelevanceEnum
    traversedPort: Optional[int] = None
    traversedService: Optional[str] = None
    affectedService: Optional[str] = None
    effectiveWeight: float = 0.20
    rationale: str

class PathRiskFactors(BaseModel):
    entryThreatProbability: float = 0.87
    maximumNodeRisk: float = 60.80          # Highest risk among nodes in path
    cumulativeVulnerabilityExposure: float = 0.80
    targetCriticality: float = 1.00        # Criticality of crown jewel
    attackImpact: float = 1.00             # Modeled impact of attack category
    pathLength: int = 3
    reachableEdges: int = 3
    securityControlStrength: float = 0.50  # Filtering damping

class AttackPathRisk(BaseModel):
    scoringId: str = Field(default_factory=lambda: f"PRISK-{uuid.uuid4().hex[:6].upper()}")
    pathId: str
    nodeSequence: List[str]
    score: float
    scoreFormatted: str
    level: RiskLevelTier
    factors: PathRiskFactors

    # Fractional Contributions
    threatContribution: float
    vulnerabilityContribution: float
    assetContribution: float
    impactContribution: float
    reachabilityMultiplier: float

    criticalTarget: bool = False
    vulnerabilityAssessments: List[VulnerabilityRelevanceAssessment] = Field(default_factory=list)
    explanation: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_formatted_summary(self) -> str:
        chain = " -> ".join(self.nodeSequence)
        return (
            f"AttackPathRisk [{self.scoringId}] for {chain}\n"
            f"Score: {self.scoreFormatted} | Tier: {self.level.value} | Critical Target: {self.criticalTarget}\n"
            f"Contributions: MaxNodeRisk={self.factors.maximumNodeRisk:.1f}, TargetCrit={self.factors.targetCriticality:.2f}, "
            f"Vuln={self.factors.cumulativeVulnerabilityExposure:.2f}, ReachMult={self.reachabilityMultiplier:.2f}\n"
            f"Reasoning: {self.explanation}"
        )

class RankedPathItem(BaseModel):
    rank: int
    pathId: str
    nodeSequence: List[str]
    riskScore: float
    riskLevel: RiskLevelTier
    status: str
    criticalTarget: bool
    explanation: str

class PathRankingResult(BaseModel):
    rankingId: str = Field(default_factory=lambda: f"PRANK-{uuid.uuid4().hex[:6].upper()}")
    rankedPaths: List[RankedPathItem]
    highestRiskPathId: str
    highestRiskScore: float
    highestRiskLevel: RiskLevelTier
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())