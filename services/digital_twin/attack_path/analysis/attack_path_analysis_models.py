from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.graph_models import PathStatusEnum
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.scoring.path_scoring_models import RankedPathItem, AttackPathRisk
from services.digital_twin.attack_path.visualization.path_visual_models import ComprehensivePathExplanationReport

class AnalysisStatusEnum(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    NO_PATH_FOUND = "NO_PATH_FOUND"
    FAILED = "FAILED"

class AttackPathAuditRecord(BaseModel):
    analysisId: str = Field(default_factory=lambda: f"APANA-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    graphVersion: str = "v1.0"
    source: str
    target: str
    traversalMethod: str = "DFS_ALL_BOUNDED"
    pathsDiscovered: int
    pathsBlocked: int
    pathsPartial: int
    selectedPath: Optional[List[str]] = None
    pathRiskScore: float = 0.0
    pathRiskLevel: RiskLevelTier = RiskLevelTier.LOW
    criticalTarget: bool = False
    riskEngineVersion: str = "v3.0-multiplicative"
    modelVersion: str = "rf-v1.0"
    featureVersion: str = "feature-v1.0"
    explanationId: Optional[str] = None
    status: AnalysisStatusEnum = AnalysisStatusEnum.COMPLETED

class MasterAttackPathAnalysisResult(BaseModel):
    analysisId: str
    source: str
    target: str
    rankedPaths: List[RankedPathItem]
    topPathExplanation: Optional[ComprehensivePathExplanationReport] = None
    auditRecord: AttackPathAuditRecord
    executionLatencyMs: Dict[str, float] = Field(default_factory=dict)

    def to_soc_summary(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                 DIGITAL TWIN ATTACK PATH ANALYSIS REPORT                     ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ Analysis ID : {self.analysisId:<28} Status: {self.auditRecord.status.value:<22} ║",
            f"║ Traversal   : {self.source} -> {self.target:<40} ║",
            f"║ Paths Found : Total={self.auditRecord.pathsDiscovered:<3} | Blocked={self.auditRecord.pathsBlocked:<3} | Partial={self.auditRecord.pathsPartial:<3} Critical Target: {str(self.auditRecord.criticalTarget):<5} ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            "║ RANKED ATTACK PATH TRAVERSALS:                                               ║"
        ]
        for p in self.rankedPaths[:4]:
            chain = " -> ".join(p.nodeSequence)
            lines.append(f"║ [{p.rank}] {chain:<42} Risk: {p.riskScore:5.2f} [{p.riskLevel.value:<8}] ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        if self.topPathExplanation:
            lines.append("║ PRIMARY PATH MITIGATION GUIDANCE:                                            ║")
            lines.append(f"║ {self.topPathExplanation.recommendedMitigation[:76]} ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)