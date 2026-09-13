from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class CanonicalAttackCategory(str, Enum):
    NORMAL = "NORMAL"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE_LIKE = "BRUTE_FORCE_LIKE"
    DOS_LIKE = "DOS_LIKE"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT_LIKE = "LATERAL_MOVEMENT_LIKE"
    EXFILTRATION_LIKE = "EXFILTRATION_LIKE"

CLASS_TO_INT: Dict[str, int] = {
    CanonicalAttackCategory.NORMAL.value: 0,
    CanonicalAttackCategory.PORT_SCAN.value: 1,
    CanonicalAttackCategory.BRUTE_FORCE_LIKE.value: 2,
    CanonicalAttackCategory.DOS_LIKE.value: 3,
    CanonicalAttackCategory.DNS_ANOMALY.value: 4,
    CanonicalAttackCategory.BEACONING.value: 5,
    CanonicalAttackCategory.LATERAL_MOVEMENT_LIKE.value: 6,
    CanonicalAttackCategory.EXFILTRATION_LIKE.value: 7
}

INT_TO_CLASS: Dict[int, str] = {v: k for k, v in CLASS_TO_INT.items()}

class MultiClassPredictionOutput(BaseModel):
    predictionId: str = Field(default_factory=lambda: f"PRED-MC-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    predictedCategory: CanonicalAttackCategory
    categoryConfidence: float = Field(..., ge=0.0, le=1.0)
    categoryConfidenceFormatted: str
    classDistribution: Dict[str, float] = Field(default_factory=dict)
    modelName: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_display_string(self) -> str:
        sorted_dist = sorted(self.classDistribution.items(), key=lambda item: item[1], reverse=True); dist_str = ", ".join(f"{k}: {round(v * 100, 1)}%" for k, v in sorted_dist[:3])
        return (
            f"Prediction ID: {self.predictionId}\n"
            f"Predicted Category: {self.predictedCategory.value}\n"
            f"Category Confidence: {self.categoryConfidence:.2f} ({self.categoryConfidenceFormatted})\n"
            f"Top Classes: [{dist_str}]\n"
            f"Model: {self.modelName}"
        )