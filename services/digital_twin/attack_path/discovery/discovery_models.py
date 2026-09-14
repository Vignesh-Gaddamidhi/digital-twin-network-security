from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.attack_path.graph.graph_models import PathStatusEnum, AttackPath

class TraversalMethodEnum(str, Enum):
    BFS_SHORTEST = "BFS_SHORTEST"
    DFS_ALL_BOUNDED = "DFS_ALL_BOUNDED"

class PathConstraints(BaseModel):
    maxDepth: int = 6
    maxPaths: int = 20
    allowedZones: Optional[List[str]] = None
    blockedZones: Optional[List[str]] = None
    allowedProtocols: Optional[List[str]] = None  # e.g., ["TCP", "UDP"]
    requiredPort: Optional[int] = None
    requiredService: Optional[str] = None

class DiscoveredPathDetail(BaseModel):
    pathId: str = Field(default_factory=lambda: f"PATH-{uuid.uuid4().hex[:6].upper()}")
    nodeSequence: List[str]
    edgeSequence: List[str]
    hopCount: int
    status: PathStatusEnum
    blockedAt: Optional[str] = None
    blockingReason: Optional[str] = None
    vulnerabilitiesEncountered: List[str] = Field(default_factory=list)
    securityControlsEncountered: List[str] = Field(default_factory=list)

class PathDiscoveryResult(BaseModel):
    analysisId: str = Field(default_factory=lambda: f"PANA-{uuid.uuid4().hex[:8].upper()}")
    source: str
    target: str
    traversalMethod: TraversalMethodEnum
    pathsFound: int
    pathsPossible: int
    pathsBlocked: int
    pathsPartial: int
    maximumDepth: int
    paths: List[DiscoveredPathDetail] = Field(default_factory=list)
    graphVersion: str = "v1.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_formatted_summary(self) -> str:
        lines = [
            "================================================================================",
            "                       ATTACK PATH DISCOVERY REPORT                             ",
            "================================================================================",
            f"Analysis ID    : {self.analysisId}",
            f"Source Node    : {self.source} -> Target Node: {self.target}",
            f"Method         : {self.traversalMethod.value} (Max Depth: {self.maximumDepth})",
            f"Summary Counts : Total={self.pathsFound} | Possible={self.pathsPossible} | Blocked={self.pathsBlocked} | Partial={self.pathsPartial}",
            "--------------------------------------------------------------------------------",
            "DISCOVERED PATHS:"
        ]
        for idx, p in enumerate(self.paths, start=1):
            chain = " -> ".join(p.nodeSequence)
            lines.append(f"  [{idx}] {chain} [{p.status.value}] ({p.hopCount} hops)")
            if p.blockedAt:
                lines.append(f"      Blocked At: {p.blockedAt} (Reason: {p.blockingReason})")
            if p.vulnerabilitiesEncountered:
                lines.append(f"      Vulnerabilities: {', '.join(p.vulnerabilitiesEncountered)}")
        lines.append("================================================================================")
        return "\n".join(lines)