from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.topology_models import TopologyNodeState

class AttackPathVisualStatusEnum(str, Enum):
    POSSIBLE = "POSSIBLE"
    ACTIVE_SIMULATED = "ACTIVE_SIMULATED"
    BLOCKED = "BLOCKED"
    MITIGATED = "MITIGATED"
    HISTORICAL = "HISTORICAL"
    UNVERIFIED = "UNVERIFIED"

class ViewModeEnum(str, Enum):
    VIEW_2D = "2D"
    VIEW_3D = "3D"

class VisibilityPresetEnum(str, Enum):
    SHOW_ALL = "SHOW_ALL"
    HIDE_INACTIVE = "HIDE_INACTIVE"
    HIDE_ISOLATED = "HIDE_ISOLATED"
    SHOW_THREATENED_ONLY = "SHOW_THREATENED_ONLY"
    SHOW_HIGH_RISK_ONLY = "SHOW_HIGH_RISK_ONLY"

class TopologyFilterCriteria(BaseModel):
    deviceTypeFilter: str = "ALL"  # ALL, SERVERS, ROUTERS, SWITCHES, FIREWALLS, DATABASES, DNS, CLIENTS
    securityStateFilter: str = "ALL"  # ALL, NORMAL, SUSPICIOUS, AT_RISK, COMPROMISED, ISOLATED
    riskLevelFilter: str = "ALL"  # ALL, LOW, MEDIUM, HIGH, CRITICAL
    threatFilter: str = "ALL"  # ALL, NO_THREAT, THREATENED, ACTIVE_THREAT
    visibilityPreset: VisibilityPresetEnum = VisibilityPresetEnum.SHOW_ALL

class AttackPath3DVisualDetail(BaseModel):
    pathId: str
    entryDeviceId: str
    targetDeviceId: str
    traversedNodeSequence: List[str]
    traversedEdgeIds: List[str]
    riskScore: float
    riskLevel: RiskLevelTier
    likelihoodScore: float
    impactScore: float
    status: AttackPathVisualStatusEnum
    vulnerabilitiesExploited: List[str] = Field(default_factory=list)
    reachability: str = "REACHABLE"
    isHighlighted: bool = False

class ViewportSyncState(BaseModel):
    activeViewMode: ViewModeEnum = ViewModeEnum.VIEW_3D
    selectedDeviceId: Optional[str] = None
    selectedPathId: Optional[str] = None
    activeFilters: TopologyFilterCriteria = Field(default_factory=TopologyFilterCriteria)
    timeRange: str = "30m"
    lastSwitchedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ViewportSwitchResponse(BaseModel):
    previousMode: ViewModeEnum
    currentMode: ViewModeEnum
    syncState: ViewportSyncState
    targetCoordinates: Dict[str, float]
    preservedContext: Dict[str, Any]