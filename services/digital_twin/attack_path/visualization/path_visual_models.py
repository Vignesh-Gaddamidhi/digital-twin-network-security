from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class PathVisualStateEnum(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    AT_RISK = "AT_RISK"
    POTENTIAL_ATTACK_PATH = "POTENTIAL_ATTACK_PATH"
    HIGH_RISK_PATH = "HIGH_RISK_PATH"
    CRITICAL_PATH = "CRITICAL_PATH"
    BLOCKED_PATH = "BLOCKED_PATH"

class NodeVisualCard(BaseModel):
    deviceId: str
    hostname: str
    zone: str
    deviceType: str
    assetCriticality: str
    riskScore: float
    riskLevel: RiskLevelTier
    openPorts: List[int]
    services: List[str]
    activeVulnerabilities: List[str]
    vulnerabilityCount: int
    securityState: str
    reachable: bool

class EdgeVisualCard(BaseModel):
    edgeId: str
    sourceNode: str
    destinationNode: str
    directedNotation: str  # e.g., "WEB-01 -> DB-01"
    protocol: str
    destinationPort: int
    service: str
    reachability: str     # REACHABLE, RESTRICTED, BLOCKED
    securityControl: str
    connectionId: str

class AttackPathVisualPanel(BaseModel):
    pathId: str
    source: str
    entryNode: str
    targetNode: str
    nodeSequence: List[str]
    pathLength: int
    reachability: str
    riskScore: float
    riskScoreFormatted: str
    riskLevel: RiskLevelTier
    visualState: PathVisualStateEnum
    criticalTarget: bool
    explanation: str

class GraphVisualizationFilter(BaseModel):
    riskLevel: Optional[RiskLevelTier] = None
    zone: Optional[str] = None
    deviceType: Optional[str] = None
    hasVulnerabilities: Optional[bool] = None
    reachability: Optional[str] = None
    criticalTargetOnly: bool = False

class ComprehensivePathExplanationReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"PEXP-{uuid.uuid4().hex[:6].upper()}")
    pathId: str
    nodeSequence: List[str]
    directedChainString: str
    visualState: PathVisualStateEnum
    pathRiskScore: float
    pathRiskLevel: RiskLevelTier
    criticalTarget: bool
    mlEvidence: str
    riskEvidence: str
    graphTopologyEvidence: str
    combinedExplanation: str
    recommendedMitigation: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_formatted_cli_card(self) -> str:
        chain = " -> ".join(self.nodeSequence)
        return (
            "================================================================================\n"
            "                      ATTACK PATH FORENSIC EXPLANATION                          \n"
            "================================================================================\n"
            f"Path ID        : {self.pathId}\n"
            f"Route Traversal: {chain}\n"
            f"Risk Level     : {self.pathRiskLevel.value} (Score: {self.pathRiskScore:.2f}/100.0) | State: {self.visualState.value}\n"
            f"Critical Target: {'YES - Crown Jewel at Risk' if self.criticalTarget else 'NO'}\n"
            "--------------------------------------------------------------------------------\n"
            f"[ML TELEMETRY ATTRIBUTION]\n{self.mlEvidence}\n\n"
            f"[CONTEXTUAL ASSET RISK]\n{self.riskEvidence}\n\n"
            f"[GRAPH TOPOLOGY TRAVERSAL]\n{self.graphTopologyEvidence}\n\n"
            f"[SYNTHESIZED FORENSIC NARRATIVE]\n{self.combinedExplanation}\n\n"
            f"[RECOMMENDED MITIGATION]\n{self.recommendedMitigation}\n"
            "================================================================================"
        )