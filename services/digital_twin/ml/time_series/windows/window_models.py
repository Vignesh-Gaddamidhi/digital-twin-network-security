from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class SlidingWindowConfig(BaseModel):
    windowSize: int = Field(default=10, ge=2, description="Number of historical time steps (T)")
    stepSize: int = Field(default=1, ge=1, description="Stride between sliding steps (S)")
    predictionHorizon: int = Field(default=3, ge=1, description="Number of future steps to predict ahead (H)")
    minSequenceLength: int = Field(default=13, ge=3, description="Minimum sequence length (T + H)")
    featureDim: int = Field(default=16, description="Dimension of flat feature vector D")

class TemporalSequence(BaseModel):
    sequenceId: str = Field(default_factory=lambda: f"SEQ-{uuid.uuid4().hex[:8].upper()}")
    startIndex: int
    endIndex: int
    horizonStartIndex: int
    horizonEndIndex: int
    timeTimestamps: List[str] = Field(default_factory=list)
    featureMatrix: List[List[float]] = Field(default_factory=list)  # Shape: [T, D]
    futureThreatBinary: int = 0
    futureThreatCategory: str = "NORMAL"
    futureThreatProbabilityTarget: float = 0.0
    sequenceStage: str = "BASELINE"  # BASELINE, EARLY_INDICATORS, ESCALATION, IMPACT
    metadata: Dict[str, Any] = Field(default_factory=dict)