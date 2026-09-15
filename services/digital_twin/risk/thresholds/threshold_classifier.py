from typing import Dict, Any, Tuple, Optional
from pydantic import BaseModel, Field

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class RiskThresholdConfig(BaseModel):
    lowUpperBound: float = 25.0       # [0, 25) -> LOW
    mediumUpperBound: float = 50.0    # [25, 50) -> MEDIUM
    highUpperBound: float = 75.0      # [50, 75) -> HIGH
    criticalUpperBound: float = 100.0 # [75, 100] -> CRITICAL
    version: str = "v1.0"

class ThresholdClassifier:
    """Classifies raw 0-100 risk scores into discrete operational risk tiers based on configurable boundaries."""

    def __init__(self, config: Optional[RiskThresholdConfig] = None):
        self.config = config or RiskThresholdConfig()

    def classify(self, score: float) -> RiskLevelTier:
        s = round(float(score), 4)
        if s < self.config.lowUpperBound:
            return RiskLevelTier.LOW
        elif s < self.config.mediumUpperBound:
            return RiskLevelTier.MEDIUM
        elif s < self.config.highUpperBound:
            return RiskLevelTier.HIGH
        else:
            return RiskLevelTier.CRITICAL

    def get_boundaries(self) -> Dict[str, Any]:
        return {
            "LOW": f"[0.0, {self.config.lowUpperBound})",
            "MEDIUM": f"[{self.config.lowUpperBound}, {self.config.mediumUpperBound})",
            "HIGH": f"[{self.config.mediumUpperBound}, {self.config.highUpperBound})",
            "CRITICAL": f"[{self.config.highUpperBound}, {self.config.criticalUpperBound}]",
            "version": self.config.version
        }

threshold_classifier = ThresholdClassifier()