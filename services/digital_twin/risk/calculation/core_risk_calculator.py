import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[4]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine"
CALC_FILE = RISK_ARTIFACTS_DIR / "risk_calculations.json"

from services.digital_twin.risk.factors.factor_types import (
    AssetCriticalityLevel, VulnerabilitySeverityLevel, AttackImpactLevel,
    RiskLevelTier, FACTOR_NORMALIZATION_MAP
)
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.risk.calculation.calculation_models import (
    RiskFactorBreakdown, RiskCalculationResult
)

class CoreRiskCalculator:
    """Computes exact multiplicative risk scores (T * A * V * I * 100.0) with defensive failure checks."""

    VERSION = "v3.0-multiplicative"

    def __init__(self, artifacts_dir: Path = RISK_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.history: List[RiskCalculationResult] = []

    @staticmethod
    def _validate_numeric_factor(name: str, val: Any) -> float:
        if val is None:
            raise ValueError(f"Missing required factor: '{name}' cannot be null.")
        if not isinstance(val, (int, float)):
            raise ValueError(f"Factor '{name}' must be numeric, got: {type(val).__name__}")
        if math.isnan(val) or math.isinf(val):
            raise ValueError(f"Factor '{name}' cannot be NaN or Infinity, got: {val}")
        f_val = float(val)
        if f_val < 0.0 or f_val > 1.0:
            raise ValueError(f"Factor '{name}' must be within [0.0, 1.0], received: {f_val}")
        return f_val

    def compute_risk(
        self,
        prediction_id: str,
        device_id: str,
        threat_probability: float,
        asset_criticality: float,
        vulnerability_score: float,
        attack_impact_score: float,
        asset_criticality_level: str = "CRITICAL",
        vulnerability_level: str = "HIGH",
        attack_impact_level: str = "CRITICAL"
    ) -> RiskCalculationResult:
        if not prediction_id or not prediction_id.strip():
            raise ValueError("Missing required parameter: 'predictionId' cannot be empty.")
        if not device_id or not device_id.strip():
            raise ValueError("Missing required parameter: 'deviceId' cannot be empty.")

        # 1. Validate all 4 numeric factors
        t = self._validate_numeric_factor("threat_probability", threat_probability)
        a = self._validate_numeric_factor("asset_criticality", asset_criticality)
        v = self._validate_numeric_factor("vulnerability_score", vulnerability_score)
        i = self._validate_numeric_factor("attack_impact_score", attack_impact_score)

        # 2. Compute Raw and Display Risk Scores
        raw_risk = round(t * a * v * i, 6)
        risk_score = round(raw_risk * 100.0, 2)

        # 3. Classify Risk Level Tier
        tier = threshold_classifier.classify(risk_score)

        # 4. Construct Factor Breakdown & Contributing Factors
        factors = RiskFactorBreakdown(
            threatProbability=t,
            threatFormatted=f"{round(t * 100, 1)}%",
            assetCriticality=a,
            assetCriticalityLevel=asset_criticality_level,
            vulnerabilityScore=v,
            vulnerabilitySeverityLevel=vulnerability_level,
            attackImpactScore=i,
            attackImpactLevel=attack_impact_level
        )

        contributing = {
            "threatProbability": f"{round(t * 100, 1)}%",
            "assetCriticality": asset_criticality_level,
            "vulnerability": vulnerability_level,
            "attackImpact": attack_impact_level
        }

        formula_proof = f"{t:.4f} Ã— {a:.4f} Ã— {v:.4f} Ã— {i:.4f} = {raw_risk:.6f} â†’ {risk_score:.2f} / 100.0"

        result = RiskCalculationResult(
            predictionId=prediction_id.strip(),
            deviceId=device_id.strip(),
            rawRiskScore=raw_risk,
            riskScore=risk_score,
            riskScoreFormatted=f"{risk_score:.2f} / 100.0",
            riskLevel=tier,
            factors=factors,
            contributingFactors=contributing,
            formulaProof=formula_proof,
            riskEngineVersion=self.VERSION,
            factorConfigVersion="v1.0",
            thresholdConfigVersion=threshold_classifier.config.version,
            status="CALCULATED"
        )

        self.history.append(result)
        self._persist_calculation(result)
        return result

    def _persist_calculation(self, calc: RiskCalculationResult):
        existing = []
        if CALC_FILE.exists():
            try:
                with open(CALC_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(calc.model_dump())
        existing = existing[-100:]
        with open(CALC_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        if CALC_FILE.exists():
            try:
                CALC_FILE.unlink()
            except Exception:
                pass

core_risk_calculator = CoreRiskCalculator()