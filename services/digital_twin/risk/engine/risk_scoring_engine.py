import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[4]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine"
ASSESSMENTS_FILE = RISK_ARTIFACTS_DIR / "risk_assessments.json"

from services.digital_twin.risk.factors.factor_types import (
    AssetCriticalityLevel, VulnerabilitySeverityLevel, AttackImpactLevel,
    RiskLevelTier, RiskAssessmentStatus, FACTOR_NORMALIZATION_MAP
)
from services.digital_twin.risk.validation.risk_schema import RiskAssessment

class RiskScoringEngine:
    """Calculates normalized multiplicative risk scores across threat, asset, vulnerability, and impact."""

    VERSION = "v3.0-multiplicative"

    def __init__(self, artifacts_dir: Path = RISK_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.history: List[RiskAssessment] = []

    @staticmethod
    def normalize_factor(value: Any, default: float = 0.20) -> float:
        if isinstance(value, (int, float)):
            return max(0.0, min(1.0, float(value)))
        if hasattr(value, "value"):
            key = str(value.value).upper()
        elif hasattr(value, "name"):
            key = str(value.name).upper()
        else:
            key = str(value).upper()
        return FACTOR_NORMALIZATION_MAP.get(key, default)

    @staticmethod
    def classify_risk_tier(score: float) -> RiskLevelTier:
        if score >= 70.0:
            return RiskLevelTier.CRITICAL
        elif score >= 45.0:
            return RiskLevelTier.HIGH
        elif score >= 20.0:
            return RiskLevelTier.MEDIUM
        else:
            return RiskLevelTier.LOW

    def calculate_risk(
        self,
        prediction_id: str,
        device_id: str,
        threat_probability: float,
        asset_criticality: AssetCriticalityLevel,
        vulnerability_severity: VulnerabilitySeverityLevel,
        attack_impact: AttackImpactLevel,
        source: str = "CLIENT-01",
        destination: str = "SERVER-01",
        predicted_category: str = "NORMAL"
    ) -> RiskAssessment:
        # 1. Validate Threat Probability bounds
        if threat_probability < 0.0 or threat_probability > 1.0:
            raise ValueError(f"Invalid threat probability: {threat_probability}. Must be in [0.0, 1.0].")

        # 2. Extract Normalized Numeric Weights
        c_weight = self.normalize_factor(asset_criticality)
        v_weight = self.normalize_factor(vulnerability_severity)
        i_weight = self.normalize_factor(attack_impact)

        # 3. Multiplicative Calculation: P * C * V * I
        raw_risk = round(threat_probability * c_weight * v_weight * i_weight, 4)
        risk_score = round(raw_risk * 100.0, 2)
        tier = self.classify_risk_tier(risk_score)

        # 4. Synthesize Fact-Based Contributing Factors
        factors = [
            f"Threat likelihood assessed at {threat_probability*100:.1f}% ({predicted_category})",
            f"Target asset criticality is {asset_criticality.value} (normalized: {c_weight:.2f})",
            f"Vulnerability exposure rating is {vulnerability_severity.value} (normalized: {v_weight:.2f})",
            f"Category impact severity potential is {attack_impact.value} (normalized: {i_weight:.2f})"
        ]

        explanation = (
            f"Calculated {tier.value} risk ({risk_score}/100) based on {threat_probability*100:.1f}% threat probability "
            f"targeting a {asset_criticality.value} criticality host with {vulnerability_severity.value} vulnerability rating."
        )

        assessment = RiskAssessment(
            predictionId=prediction_id,
            deviceId=device_id,
            source=source,
            destination=destination,
            threatProbability=threat_probability,
            assetCriticality=asset_criticality,
            vulnerabilitySeverity=vulnerability_severity,
            attackImpact=attack_impact,
            assetCriticalityWeight=c_weight,
            vulnerabilityWeight=v_weight,
            attackImpactWeight=i_weight,
            rawRiskScore=raw_risk,
            riskScore=risk_score,
            riskLevel=tier,
            contributingFactors=factors,
            explanation=explanation,
            riskEngineVersion=self.VERSION,
            status=RiskAssessmentStatus.CALCULATED
        )

        self.history.append(assessment)
        self._persist_assessment(assessment)
        return assessment

    def _persist_assessment(self, assessment: RiskAssessment):
        existing = []
        if ASSESSMENTS_FILE.exists():
            try:
                with open(ASSESSMENTS_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(assessment.model_dump())
        existing = existing[-100:]
        with open(ASSESSMENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        if ASSESSMENTS_FILE.exists():
            try:
                ASSESSMENTS_FILE.unlink()
            except Exception:
                pass

risk_scoring_engine = RiskScoringEngine()