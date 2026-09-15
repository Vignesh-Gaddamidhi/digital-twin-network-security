from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.topology_models import TopologyNodeState
from frontend.dashboard.device_inspection_models import EpistemicProvenanceEnum

class ThreatBeacon3D(BaseModel):
    beaconId: str = Field(default_factory=lambda: f"BCN-{uuid.uuid4().hex[:6].upper()}")
    eventId: str
    eventType: str
    severity: RiskLevelTier
    confidence: float
    detectionSource: str
    pulsingSpeed: float = 2.0
    colorHex: str = "#EF4444"

class VulnerabilityBadge3D(BaseModel):
    vulnerabilityId: str
    cveName: str
    severity: str
    affectedService: str
    affectedVersion: str
    status: str = "OPEN"  # OPEN, PATCHED

class RiskBreakdown3D(BaseModel):
    riskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    assetCriticality: str
    vulnerabilityFactor: float
    attackImpact: float
    formulaString: str = "P(threat) × C(asset) × V(vuln) × I(impact)"

class DeviceSecurity3DVisual(BaseModel):
    deviceId: str
    securityState: TopologyNodeState
    provenance: EpistemicProvenanceEnum = EpistemicProvenanceEnum.SIMULATION
    haloColorHex: str
    emissiveIntensity: float
    pulseFrequencyHz: float
    hasIsolationCage: bool = False
    hasThreatBeacon: bool = False
    activeBeacon: Optional[ThreatBeacon3D] = None
    risk: RiskBreakdown3D
    vulnerabilities: List[VulnerabilityBadge3D] = Field(default_factory=list)

class SecurityRendererSnapshot(BaseModel):
    totalDevices: int
    compromisedCount: int
    isolatedCount: int
    atRiskCount: int
    activeBeaconsCount: int
    securityVisuals: Dict[str, DeviceSecurity3DVisual] = Field(default_factory=dict)