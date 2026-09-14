from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import (
    AssetCriticalityLevel, VulnerabilitySeverityLevel, AttackImpactLevel,
    RiskLevelTier, RiskAssessmentStatus
)

class RiskAssessment(BaseModel):
    riskId: str = Field(default_factory=lambda: f"RISK-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    predictionId: str
    deviceId: str
    source: str = "EXTERNAL_ROUTER"
    destination: str = "CORE_SERVER"

    # The 4 Required Factors (Values & Normalized Weights)
    threatProbability: float
    assetCriticality: AssetCriticalityLevel
    vulnerabilitySeverity: VulnerabilitySeverityLevel
    attackImpact: AttackImpactLevel

    assetCriticalityWeight: float
    vulnerabilityWeight: float
    attackImpactWeight: float

    # Quantitative Scores
    rawRiskScore: float  # P_threat * C_asset * V_asset * I_attack in [0.0, 1.0]
    riskScore: float     # rawRiskScore * 100.0 in [0.0, 100.0]
    riskLevel: RiskLevelTier

    # Explainability & Evidence
    contributingFactors: List[str] = Field(default_factory=list)
    explanation: str = ""

    # Provenance & Audit
    modelVersion: str = "rf-v1.0"
    featureVersion: str = "feature-v1.0"
    riskEngineVersion: str = "v3.0-multiplicative"
    status: RiskAssessmentStatus = RiskAssessmentStatus.CALCULATED

    @field_validator("threatProbability")
    @classmethod
    def validate_threat_probability(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError(f"threatProbability must be within [0.0, 1.0], received: {v}")
        return float(v)

    @field_validator("rawRiskScore")
    @classmethod
    def validate_raw_risk(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError(f"rawRiskScore must be within [0.0, 1.0], received: {v}")
        return float(v)

    @field_validator("riskScore")
    @classmethod
    def validate_risk_score(cls, v: float) -> float:
        if v < 0.0 or v > 100.0:
            raise ValueError(f"riskScore must be within [0.0, 100.0], received: {v}")
        return float(v)

    def to_formatted_card(self) -> str:
        return (
            f"╔════════════════════════════════════════════════════════════════════╗\n"
            f"║                      RISK ASSESSMENT CARD                          ║\n"
            f"╠════════════════════════════════════════════════════════════════════╣\n"
            f"║ Risk ID: {self.riskId:<26} Status: {self.status.value:<22} ║\n"
            f"║ Device : {self.deviceId:<26} Target: {self.destination:<22} ║\n"
            f"╠════════════════════════════════════════════════════════════════════╣\n"
            f"║ Threat Probability    : {self.threatProbability*100:<6.1f}% (Weight: {self.threatProbability:<4.2f})               ║\n"
            f"║ Asset Criticality     : {self.assetCriticality.value:<10} (Weight: {self.assetCriticalityWeight:<4.2f})               ║\n"
            f"║ Vulnerability Severity: {self.vulnerabilitySeverity.value:<10} (Weight: {self.vulnerabilityWeight:<4.2f})               ║\n"
            f"║ Attack Impact         : {self.attackImpact.value:<10} (Weight: {self.attackImpactWeight:<4.2f})               ║\n"
            f"╠════════════════════════════════════════════════════════════════════╣\n"
            f"║ Raw Risk Formulation  : {self.threatProbability:.2f} × {self.assetCriticalityWeight:.2f} × {self.vulnerabilityWeight:.2f} × {self.attackImpactWeight:.2f} = {self.rawRiskScore:.4f}         ║\n"
            f"║ Operational Risk Score: {self.riskScore:<6.2f} / 100.0  Tier: {self.riskLevel.value:<15}     ║\n"
            f"╚════════════════════════════════════════════════════════════════════╝"
        )