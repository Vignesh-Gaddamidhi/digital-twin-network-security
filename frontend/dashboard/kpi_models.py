from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class DevicesKPICard(BaseModel):
    totalDevices: int = 0
    healthyDevices: int = 0
    atRiskDevices: int = 0
    isolatedDevices: int = 0
    subtitle: str = "10 Healthy, 1 At Risk, 1 Isolated"

class ThreatsKPICard(BaseModel):
    totalThreats: int = 0
    criticalThreats: int = 0
    highThreats: int = 0
    mediumThreats: int = 0
    lowThreats: int = 0
    subtitle: str = "Critical: 1, High: 2, Medium: 2"

class RiskKPICard(BaseModel):
    overallRiskLevel: RiskLevelTier = RiskLevelTier.LOW
    overallRiskScore: float = 0.0
    riskTrendSymbol: str = "→"  # ↑, ↓, →, ~
    riskTrendDirection: str = "STABLE"
    highestRiskDevice: str = "NONE"
    highestRiskPath: Optional[str] = None
    subtitle: str = "Risk Score: 0.0 | Trend: →"

class AttacksKPICard(BaseModel):
    totalAttacks: int = 0
    detectedAttacks: int = 0
    predictedAttacks: int = 0
    simulatedAttacks: int = 0
    activeAttackPaths: int = 0
    subtitle: str = "Detected: 1, Predicted: 1, Simulated: 1"

class MasterKPISnapshot(BaseModel):
    snapshotId: str = Field(default_factory=lambda: f"KPI-{uuid.uuid4().hex[:6].upper()}")
    devices: DevicesKPICard = Field(default_factory=DevicesKPICard)
    threats: ThreatsKPICard = Field(default_factory=ThreatsKPICard)
    risk: RiskKPICard = Field(default_factory=RiskKPICard)
    attacks: AttacksKPICard = Field(default_factory=AttacksKPICard)
    lastRefreshedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    isStale: bool = False

    def to_formatted_cli_card(self) -> str:
        d = self.devices
        t = self.threats
        r = self.risk
        a = self.attacks
        lines = [
            "┌──────────────────────────────────────────────────────────────────────────────┐",
            "│                     DIGITAL TWIN TOP-LEVEL KPI METRICS                       │",
            "├────────────────┬────────────────┬────────────────┬───────────────────────────┤",
            f"│    DEVICES     │    THREATS     │      RISK      │          ATTACKS          │",
            f"│       {d.totalDevices:02d}       │       {t.totalThreats:02d}       │      {r.overallRiskLevel.value:<8}  │            {a.totalAttacks:02d}             │",
            f"│ {d.healthyDevices} Healthy      │ {t.criticalThreats} Critical    │ Score: {r.overallRiskScore:4.1f}    │ {a.detectedAttacks} Detected                │",
            f"│ {d.atRiskDevices} At Risk      │ {t.highThreats} High        │ Trend: {r.riskTrendSymbol}       │ {a.predictedAttacks} Predicted               │",
            f"│ {d.isolatedDevices} Isolated     │ {t.mediumThreats} Medium      │ Peak: {r.highestRiskDevice:<9} │ {a.simulatedAttacks} Simulated               │",
            "└────────────────┴────────────────┴────────────────┴───────────────────────────┘"
        ]
        return "\n".join(lines)