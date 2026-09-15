from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class PathFilterTypeEnum(str, Enum):
    ALL = "ALL"
    HIGHEST_RISK = "HIGHEST_RISK"
    CRITICAL_ASSETS = "CRITICAL_ASSETS"
    REACHABLE = "REACHABLE"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    ACTIVE = "ACTIVE"
    HISTORICAL = "HISTORICAL"

class AttackPathItemCard(BaseModel):
    pathId: str
    rank: int
    entryPoint: str
    targetNode: str
    nodeSequence: List[str]
    hopCount: int
    reachability: str       # REACHABLE, PARTIALLY_REACHABLE, BLOCKED
    riskScore: float
    riskLevel: RiskLevelTier
    status: str             # POSSIBLE, BLOCKED, PARTIALLY_REACHABLE
    criticalTarget: bool = False
    traversedServices: List[str] = Field(default_factory=list)
    vulnerabilitiesExposed: List[str] = Field(default_factory=list)
    shortExplanation: str = ""

class TopologyHighlightState(BaseModel):
    activePathId: Optional[str] = None
    highlightedNodes: List[str] = Field(default_factory=list)
    highlightedEdges: List[str] = Field(default_factory=list)
    severedEdges: List[str] = Field(default_factory=list)
    targetNodeId: Optional[str] = None

class AttackPathDetailedView(BaseModel):
    selectedPath: AttackPathItemCard
    highlightState: TopologyHighlightState
    
    # Path -> Risk factors
    threatProbability: float = 0.88
    maxIntermediateRisk: float = 69.6
    targetCriticalityWeight: float = 1.00
    vulnerabilityWeight: float = 1.00
    attackImpactWeight: float = 0.80
    
    # Path -> XAI Attribution
    xaiAttributionText: str = ""
    originatingFeatures: List[str] = Field(default_factory=list)
    
    # Actionable containment
    recommendedContainment: str = ""

class AttackPathDashboardSnapshot(BaseModel):
    snapshotId: str = Field(default_factory=lambda: f"APSNAP-{uuid.uuid4().hex[:6].upper()}")
    totalDiscoveredPaths: int
    activeFilter: PathFilterTypeEnum = PathFilterTypeEnum.ALL
    rankedPaths: List[AttackPathItemCard] = Field(default_factory=list)
    selectedPathDetail: Optional[AttackPathDetailedView] = None
    lastAnalyzedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_panel(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                      ATTACK PATH ANALYSIS DASHBOARD                          ║",
            f"║ Total Paths: {self.totalDiscoveredPaths:<3} │ Filter: [{self.activeFilter.value:<15}] │ Analyzed: {self.lastAnalyzedAt[11:19]}      ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            "║ RANKED ATTACK PATH TRAVERSALS:                                               ║"
        ]
        for p in self.rankedPaths[:4]:
            chain = " ──> ".join(p.nodeSequence)
            lines.append(f"║ #{p.rank} [{p.pathId:<8}] {chain:<43} [{p.riskLevel.value:<8}] ({p.riskScore:4.1f}) ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        if self.selectedPathDetail:
            d = self.selectedPathDetail
            lines.append(f"║ SELECTED PATH: {d.selectedPath.pathId} ({d.selectedPath.reachability}) Target Crown Jewel: {d.selectedPath.targetNode:<10} ║")
            lines.append(f"║ HIGHLIGHTED NODES: {', '.join(d.highlightState.highlightedNodes):<57} ║")
            lines.append(f"║ RISK FACTORS: Threat: {d.threatProbability*100:.0f}% │ Target Crit: {d.targetCriticalityWeight:.2f} │ Vuln: {d.vulnerabilityWeight:.2f} │ Impact: {d.attackImpactWeight:.2f} ║")
            lines.append(f"║ XAI ORIGIN: {d.xaiAttributionText[:64]} ║")
            lines.append(f"║ MITIGATION: {d.recommendedContainment[:64]} ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)