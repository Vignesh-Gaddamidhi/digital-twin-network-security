from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class RiskFactorBreakdown(BaseModel):
    threatProbability: float
    threatFormatted: str
    assetCriticality: float
    assetCriticalityLevel: str
    vulnerabilityScore: float
    vulnerabilitySeverityLevel: str
    attackImpactScore: float
    attackImpactLevel: str

class RiskCalculationResult(BaseModel):
    calculationId: str = Field(default_factory=lambda: f"CALC-{uuid.uuid4().hex[:8].upper()}")
    predictionId: str
    deviceId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Raw and Display Precision
    rawRiskScore: float
    riskScore: float
    riskScoreFormatted: str
    riskLevel: RiskLevelTier

    # Detailed Factor Lineage
    factors: RiskFactorBreakdown
    contributingFactors: Dict[str, Any]
    formulaProof: str

    # Configuration & Engine Versioning
    riskEngineVersion: str = "v3.0-multiplicative"
    factorConfigVersion: str = "v1.0"
    thresholdConfigVersion: str = "v1.0"
    status: str = "CALCULATED"

    def to_summary_string(self) -> str:
        return (
            f"RiskCalculation: {self.calculationId} (Prediction: {self.predictionId})\n"
            f"Device: {self.deviceId} | Risk Score: {self.riskScore:.2f} / 100.0 [{self.riskLevel.value}]\n"
            f"Factors: T={self.factors.threatProbability:.2f} × A={self.factors.assetCriticality:.2f} × "
            f"V={self.factors.vulnerabilityScore:.2f} × I={self.factors.attackImpactScore:.2f} = {self.rawRiskScore:.4f}\n"
            f"Proof: {self.formulaProof}"
        )