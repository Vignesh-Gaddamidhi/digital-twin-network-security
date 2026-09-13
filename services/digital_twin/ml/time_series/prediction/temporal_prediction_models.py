from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class TemporalPrediction(BaseModel):
    predictionId: str = Field(default_factory=lambda: f"TPRED-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    deviceId: str = "SERVER-01"
    targetDevice: str = "GATEWAY-01"
    sequenceStart: int
    sequenceEnd: int
    predictionHorizon: int = 3
    intervalSeconds: float = 5.0

    # Decoupled Dual Probabilities
    currentThreatProbability: float
    currentThreatProbabilityFormatted: str
    futureThreatProbability: float
    futureThreatProbabilityFormatted: str

    # Attack Signature & Timing
    predictedCategory: str = "DOS_LIKE"
    categoryConfidence: float = 0.90
    categoryConfidenceFormatted: str = "90.0%"
    predictedImpactStage: str = "ESCALATION"  # BASELINE, EARLY_INDICATORS, ESCALATION, IMPACT, RECOVERY
    leadTimeSeconds: float = 35.0
    leadTimeFormatted: str = "35.0 seconds"

    # Contextual Risk
    riskScore: float
    riskLevel: str
    earlyWarningStatus: str  # NO_WARNING, WATCH, EARLY_WARNING, HIGH_CONFIDENCE_WARNING, IMPACT_STAGE
    isEarlyWarningTriggered: bool

    # Model & Feature Lineage
    modelName: str = "lstm"
    modelVersion: str = "lstm-v1.0"
    featureVersion: str = "ts-feat-v1.0"
    status: str = "COMPLETED"

    def to_dashboard_display(self) -> str:
        return (
            "╔════════════════════════════════════════════╗\n"
            "║       DIGITAL TWIN EARLY WARNING           ║\n"
            "╠════════════════════════════════════════════╣\n"
            f"║ Device: {self.deviceId:<34} ║\n"
            f"║ Target: {self.targetDevice:<34} ║\n"
            "║                                            ║\n"
            f"║ Current Threat Probability:       {self.currentThreatProbabilityFormatted:<8} ║\n"
            f"║ Future Threat Probability:        {self.futureThreatProbabilityFormatted:<8} ║\n"
            "║                                            ║\n"
            f"║ Predicted Category:         {self.predictedCategory:<14} ║\n"
            f"║ Category Confidence:             {self.categoryConfidenceFormatted:<8} ║\n"
            "║                                            ║\n"
            f"║ Predicted Stage:             {self.predictedImpactStage:<13} ║\n"
            f"║ Risk Level:                       {self.riskLevel:<8} ║\n"
            "║                                            ║\n"
            f"║ Early Warning:                    {'YES' if self.isEarlyWarningTriggered else 'NO':<8} ║\n"
            f"║ Lead Time:                  {self.leadTimeFormatted:<14} ║\n"
            "║                                            ║\n"
            f"║ Model:                         {self.modelName.upper():<11} ║\n"
            f"║ Model Version:                 {self.modelVersion:<11} ║\n"
            "╚════════════════════════════════════════════╝"
        )