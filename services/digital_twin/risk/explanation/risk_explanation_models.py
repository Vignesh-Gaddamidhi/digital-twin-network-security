from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class RiskConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class RiskLevelPolicyItem(BaseModel):
    level: RiskLevelTier
    minimumScore: float
    maximumScore: float
    description: str
    recommendedAction: str

RISK_LEVEL_POLICIES: Dict[RiskLevelTier, RiskLevelPolicyItem] = {
    RiskLevelTier.LOW: RiskLevelPolicyItem(
        level=RiskLevelTier.LOW,
        minimumScore=0.0,
        maximumScore=25.0,
        description="Limited predicted threat and/or low-impact asset context.",
        recommendedAction="Continue standard monitoring. No immediate operational intervention required."
    ),
    RiskLevelTier.MEDIUM: RiskLevelPolicyItem(
        level=RiskLevelTier.MEDIUM,
        minimumScore=25.0,
        maximumScore=50.0,
        description="Moderate risk requiring increased monitoring and routine investigation.",
        recommendedAction="Schedule routine investigation and cross-reference IDS telemetry events."
    ),
    RiskLevelTier.HIGH: RiskLevelPolicyItem(
        level=RiskLevelTier.HIGH,
        minimumScore=50.0,
        maximumScore=75.0,
        description="Significant predicted threat involving important asset, vulnerability, or impact factors.",
        recommendedAction="Investigation should be prioritized. Prepare mitigation and segmentation playbooks."
    ),
    RiskLevelTier.CRITICAL: RiskLevelPolicyItem(
        level=RiskLevelTier.CRITICAL,
        minimumScore=75.0,
        maximumScore=100.0,
        description="Very high combined risk involving strong threat probability and highly critical asset, vulnerability, or impact conditions.",
        recommendedAction="Immediate security investigation and rapid containment playbooks recommended."
    )
}

class RiskExplanation(BaseModel):
    explanationId: str = Field(default_factory=lambda: f"REXP-{uuid.uuid4().hex[:8].upper()}")
    riskId: str
    predictionId: str
    deviceId: str

    # Dual Explanations
    threatExplanation: str  # Phase 15: WHY THE MODEL PREDICTED THE THREAT
    riskExplanation: str    # Phase 16: WHY THE THREAT IS RISKY

    # Factor Breakdown
    factorBreakdown: Dict[str, Any]
    topRiskFactors: List[str]
    mitigationContext: str

    # Actionable Metadata
    riskLevel: RiskLevelTier
    riskScore: float
    riskScoreFormatted: str
    recommendedAction: str
    riskAssessmentConfidence: RiskConfidenceLevel

    # Lineage & Disclaimers
    limitations: str = "This risk explanation represents a calculated operational assessment and does not constitute absolute proof of compromise."
    generatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_formatted_report(self) -> str:
        factors = "\n".join(f"  * {f}" for f in self.topRiskFactors)
        return (
            "================================================================================\n"
            "                      EXPLAINABLE RISK ASSESSMENT REPORT                        \n"
            "================================================================================\n"
            f"Explanation ID : {self.explanationId}\n"
            f"Risk ID        : {self.riskId} (Prediction: {self.predictionId})\n"
            f"Target Device  : {self.deviceId}\n"
            f"Risk Score     : {self.riskScoreFormatted} [{self.riskLevel.value}]\n"
            f"Risk Confidence: {self.riskAssessmentConfidence.value}\n\n"
            f"[MODEL EXPLANATION (WHY PREDICTED)]\n{self.threatExplanation}\n\n"
            f"[RISK EXPLANATION (WHY DANGEROUS)]\n{self.riskExplanation}\n\n"
            f"[PRIMARY RISK FACTORS]\n{factors}\n\n"
            f"[RECOMMENDED SOC ACTION]\n{self.recommendedAction}\n\n"
            f"[OPERATIONAL LIMITATIONS]\n{self.limitations}\n"
            "================================================================================"
        )