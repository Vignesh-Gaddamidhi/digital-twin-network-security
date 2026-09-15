from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class EarlyWarningStateEnum(str, Enum):
    NO_WARNING = "NO_WARNING"
    WATCH = "WATCH"
    EARLY_WARNING = "EARLY_WARNING"
    HIGH_CONFIDENCE_WARNING = "HIGH_CONFIDENCE_WARNING"
    IMPACT_STAGE = "IMPACT_STAGE"

class ModelForecastItem(BaseModel):
    modelName: str
    architecture: str
    futureThreatProbability: float
    confidenceScore: float
    inferenceLatencyMs: float

class EarlyWarningHistoryRecord(BaseModel):
    warningId: str = Field(default_factory=lambda: f"WARN-{uuid.uuid4().hex[:6].upper()}")
    targetDevice: str
    firstDetectedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastUpdatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    consecutiveWarningCount: int = 1
    cooldownRemainingSec: int = 0
    status: EarlyWarningStateEnum
    leadTimeSeconds: int = 42

class EarlyWarningDashboardSnapshot(BaseModel):
    snapshotId: str = Field(default_factory=lambda: f"EWDS-{uuid.uuid4().hex[:6].upper()}")
    targetDevice: str = "WEB-01"
    currentThreatProbability: float = 0.72
    futureThreatProbability: float = 0.87
    predictionHorizonSeconds: int = 60
    leadTimeSeconds: int = 42
    status: EarlyWarningStateEnum = EarlyWarningStateEnum.EARLY_WARNING

    # Model comparisons
    modelComparisons: List[ModelForecastItem] = Field(default_factory=list)

    # Historical audit
    warningHistory: List[EarlyWarningHistoryRecord] = Field(default_factory=list)
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_card(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                 TIME-SERIES EARLY-WARNING DASHBOARD                          ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ Target: {self.targetDevice:<12} Status: [{self.status.value:<23}] Horizon: {self.predictionHorizonSeconds}s    ║",
            f"║ CURRENT Threat: {self.currentThreatProbability*100:4.1f}%  ──>  FUTURE Threat (T+{self.predictionHorizonSeconds}s): {self.futureThreatProbability*100:4.1f}%       ║",
            f"║ LEAD-TIME TO MODELED IMPACT : {self.leadTimeSeconds} seconds prior to impact                      ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            "║ TEMPORAL MODEL ENSEMBLE COMPARISON:                                          ║"
        ]
        for m in self.modelComparisons:
            bar = "█" * int(m.futureThreatProbability * 25)
            lines.append(f"║   * {m.modelName:<12} ({m.architecture:<8}) : {m.futureThreatProbability*100:4.1f}% [{bar:<25}] ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        lines.append("║ RECENT WARNING AUDIT LEDGER:                                                 ║")
        for h in self.warningHistory[:3]:
            lines.append(f"║   [{h.warningId}] {h.status.value:<23} Lead: {h.leadTimeSeconds}s | Consec: {h.consecutiveWarningCount} | Cooldown: {h.cooldownRemainingSec}s ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)