from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class RiskTierDistribution(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0

class DeviceRiskRow(BaseModel):
    deviceId: str
    hostname: str
    zone: str
    riskScore: float
    riskLevel: RiskLevelTier
    threatProbability: float
    assetCriticality: str
    vulnerabilityStatus: str
    attackImpact: str
    isCriticalAsset: bool = False

class RiskTrendPoint(BaseModel):
    timestamp: str
    networkRiskScore: float
    peakDeviceId: str
    riskLevel: RiskLevelTier

class RiskDashboardSnapshot(BaseModel):
    snapshotId: str = Field(default_factory=lambda: f"RSNAP-{uuid.uuid4().hex[:6].upper()}")
    overallRiskScore: float
    overallRiskLevel: RiskLevelTier
    riskTrendSymbol: str = "→"
    riskTrendDirection: str = "STABLE"
    highestRiskDevice: str
    
    # Tier Distribution
    distribution: RiskTierDistribution
    
    # Formula & Factor Transparency
    configuredFormula: str = "Risk = Threat Probability × Asset Criticality × Vulnerability × Attack Impact"
    threatProbabilityFactor: str = "87%"
    assetCriticalityFactor: str = "HIGH (0.80)"
    vulnerabilityFactor: str = "HIGH (0.80)"
    attackImpactFactor: str = "HIGH (0.80)"
    riskExplanation: str
    
    # Device Matrix & Historical Trend
    deviceRiskMatrix: List[DeviceRiskRow] = Field(default_factory=list)
    trendSeries: List[RiskTrendPoint] = Field(default_factory=list)
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_panel(self) -> str:
        d = self.distribution
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                          RISK DASHBOARD OVERVIEW                             ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ Overall Risk: {self.overallRiskScore:5.1f} / 100.0 [{self.overallRiskLevel.value:<8}]  Trend: {self.riskTrendSymbol} ({self.riskTrendDirection:<10}) Peak: {self.highestRiskDevice:<10} ║",
            f"║ Distribution: LOW: {d.low:<2} │ MEDIUM: {d.medium:<2} │ HIGH: {d.high:<2} │ CRITICAL: {d.critical:<2}                           ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ FORMULA: {self.configuredFormula:<67} ║",
            f"║ FACTORS: Threat: {self.threatProbabilityFactor:<5} │ Asset: {self.assetCriticalityFactor:<11} │ Vuln: {self.vulnerabilityFactor:<10} │ Impact: {self.attackImpactFactor:<5} ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            "║ DEVICE RISK MATRIX:                                                          ║"
        ]
        for row in self.deviceRiskMatrix[:5]:
            crit_badge = "[CRITICAL ASSET]" if row.isCriticalAsset else "                "
            lines.append(f"║   * {row.deviceId:<12} ({row.zone:<8}) Score: {row.riskScore:5.1f} [{row.riskLevel.value:<8}] {crit_badge} ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣",)
        lines.append(f"║ EXPLANATION: {self.riskExplanation[:63]}... ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)