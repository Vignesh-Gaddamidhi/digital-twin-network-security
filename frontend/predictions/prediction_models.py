from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class AttackCategoryEnum(str, Enum):
    NORMAL = "NORMAL"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE_LIKE = "BRUTE_FORCE_LIKE"
    DOS_LIKE = "DOS_LIKE"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT_LIKE = "LATERAL_MOVEMENT_LIKE"
    EXFILTRATION_LIKE = "EXFILTRATION_LIKE"

class ModelMetadata(BaseModel):
    modelName: str = "Random Forest"
    modelVersion: str = "model-v1.2"
    featureVersion: str = "features-v1.0"
    timeSeriesModel: str = "LSTM"
    predictionHorizonSec: int = 60

class ShapFeatureContribution(BaseModel):
    featureName: str
    featureValue: float
    shapValue: float
    direction: str  # POSITIVE or NEGATIVE
    baselineValue: float = 0.0
    relativeImportance: float = 0.0

class LivePredictionDetail(BaseModel):
    predictionId: str = Field(default_factory=lambda: f"PRED-{uuid.uuid4().hex[:6].upper()}")
    targetDevice: str = "WEB-01"
    
    # Dual Horizon Tracking
    currentThreatProbability: float = 0.72
    futureThreatProbability: float = 0.87
    
    predictedCategory: AttackCategoryEnum = AttackCategoryEnum.PORT_SCAN
    confidenceScore: float = 0.91
    riskLevel: RiskLevelTier = RiskLevelTier.HIGH
    riskScore: float = 69.60
    
    modelInfo: ModelMetadata = Field(default_factory=ModelMetadata)
    
    # SHAP Feature Attributions
    shapContributions: List[ShapFeatureContribution] = Field(default_factory=list)
    topPositiveFeatures: List[str] = Field(default_factory=list)
    topNegativeFeatures: List[str] = Field(default_factory=list)
    
    # Plain Language Explanations
    shortExplanation: str = ""
    detailedExplanation: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_panel(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                 LIVE PREDICTIONS & EXPLAINABLE AI (XAI) PANEL                ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ Target: {self.targetDevice:<12} Category: {self.predictedCategory.value:<20} Confidence: {self.confidenceScore*100:4.1f}% ║",
            f"║ CURRENT Threat : {self.currentThreatProbability*100:4.1f}% [{self.modelInfo.modelName} {self.modelInfo.modelVersion}]                            ║",
            f"║ FUTURE Threat  : {self.futureThreatProbability*100:4.1f}% [{self.modelInfo.timeSeriesModel} Horizon: {self.modelInfo.predictionHorizonSec}s]                             ║",
            f"║ Contextual Risk: {self.riskScore:4.1f} / 100.0 [{self.riskLevel.value:<8}]                                      ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            "║ SHAP LOCAL FEATURE ATTRIBUTIONS (Top Predictors of Threat Spike):            ║"
        ]
        for c in self.shapContributions[:6]:
            sign = "+" if c.shapValue >= 0 else ""
            val_str = f"{sign}{c.shapValue:.2f}"
            bar_len = int(abs(c.shapValue) * 30)
            bar_char = "█" if c.shapValue >= 0 else "░"
            bar_str = bar_char * max(1, bar_len)
            lines.append(f"║   * {c.featureName:<24} [{val_str:>5}] {bar_str:<38} ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        lines.append("║ WHY WAS THIS PREDICTION MADE?                                                ║")
        for idx, reason in enumerate(self.detailedExplanation, start=1):
            lines.append(f"║ {idx}. {reason:<73} ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)