import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

ROOT_DIR = Path(__file__).resolve().parents[4]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine"
FINAL_RISK_FILE = RISK_ARTIFACTS_DIR / "final_risk_records.json"

from services.digital_twin.risk.factors.factor_types import (
    AssetCriticalityLevel, VulnerabilitySeverityLevel, AttackImpactLevel,
    RiskLevelTier, FACTOR_NORMALIZATION_MAP
)
from services.digital_twin.risk.factors.asset.threat_asset_engine import threat_asset_engine
from services.digital_twin.risk.factors.vulnerability.vulnerability_engine import (
    VulnerabilityRecord, VulnerabilityStatus, vulnerability_scoring_engine
)
from services.digital_twin.risk.factors.impact.attack_impact_engine import attack_impact_engine
from services.digital_twin.risk.calculation.core_risk_calculator import core_risk_calculator
from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
from services.digital_twin.risk.explanation.risk_explanation_engine import risk_explanation_engine

class FinalRiskObject(BaseModel):
    riskId: str = Field(default_factory=lambda: f"RISK-{uuid.uuid4().hex[:6].upper()}")
    predictionId: str
    deviceId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    threatProbability: float
    assetCriticality: Dict[str, Any]
    vulnerability: Dict[str, Any]
    attackImpact: Dict[str, Any]

    rawRiskScore: float
    riskScore: float
    riskLevel: str

    predictedCategory: str
    categoryConfidence: float
    topContributingFeatures: List[str]
    explanation: str

    riskTrend: str
    riskEngineVersion: str = "1.0"
    status: str = "CALCULATED"
    explanationStatus: str = "GENERATED"
    pipelineLatencyMs: Dict[str, float] = Field(default_factory=dict)

class MasterRiskOrchestrator:
    """Master orchestrator executing the full network behaviour -> ML -> XAI -> Risk -> Twin pipeline."""

    def __init__(self):
        RISK_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        self.audit_log: List[FinalRiskObject] = []

    def process_end_to_end_risk(
        self,
        prediction_id: str,
        device_id: str,
        threat_probability: Optional[float],
        predicted_category: str = "NORMAL",
        category_confidence: float = 0.90,
        xai_explanation: Optional[str] = None,
        top_contributing_features: Optional[List[str]] = None,
        custom_vulnerabilities: Optional[List[VulnerabilityRecord]] = None,
        target_service: Optional[str] = None,
        custom_attack_impact: Optional[AttackImpactLevel] = None
    ) -> FinalRiskObject:
        t0_total = time.perf_counter()
        latencies: Dict[str, float] = {}

        # 1. Defensive Validation: Threat Probability
        if threat_probability is None:
            raise ValueError("RISK_CALCULATION_FAILED: Threat probability cannot be null.")
        if threat_probability < 0.0 or threat_probability > 1.0:
            raise ValueError(f"INVALID_RISK_FACTOR: Threat probability out of bounds: {threat_probability}")

        # 2. Defensive Validation: Asset Lookup
        t0_asset = time.perf_counter()
        try:
            asset = threat_asset_engine.get_asset(device_id)
        except KeyError:
            raise KeyError(f"ASSET_CONTEXT_UNAVAILABLE: Device '{device_id}' is not registered in topology.")
        latencies["assetLookupMs"] = round((time.perf_counter() - t0_asset) * 1000, 3)

        crit_level = asset["assetCriticality"]
        crit_score = FACTOR_NORMALIZATION_MAP.get(crit_level.value, 0.40)

        # 3. Defensive Validation & Scoring: Vulnerability
        t0_vuln = time.perf_counter()
        vulns = custom_vulnerabilities or []
        vuln_res = vulnerability_scoring_engine.resolve_highest_relevant_vulnerability(vulns, target_service=target_service)
        latencies["vulnerabilityResolutionMs"] = round((time.perf_counter() - t0_vuln) * 1000, 3)

        # 4. Defensive Validation & Scoring: Attack Impact
        t0_imp = time.perf_counter()
        if custom_attack_impact is not None:
            imp_score = FACTOR_NORMALIZATION_MAP.get(custom_attack_impact.value, 0.40)
            from services.digital_twin.risk.factors.impact.attack_impact_engine import AttackImpactRecord
            impact_rec = AttackImpactRecord(
                category=predicted_category.upper(),
                impactLevel=custom_attack_impact,
                impactScore=imp_score,
                affectedAssetType=asset["deviceType"],
                affectedService=target_service or "General",
                isEscalated=False,
                rationale=f"Explicit custom attack impact {custom_attack_impact.value} applied."
            )
        else:
            impact_rec = attack_impact_engine.evaluate_impact(
                category=predicted_category,
                asset_type=asset["deviceType"],
                service=target_service or "General"
            )
        latencies["impactEvaluationMs"] = round((time.perf_counter() - t0_imp) * 1000, 3)

        # 5. Core Multiplicative Risk Calculation (T * A * V * I)
        t0_calc = time.perf_counter()
        calc = core_risk_calculator.compute_risk(
            prediction_id=prediction_id,
            device_id=device_id,
            threat_probability=threat_probability,
            asset_criticality=crit_score,
            vulnerability_score=vuln_res.effectiveScore,
            attack_impact_score=impact_rec.impactScore,
            asset_criticality_level=crit_level.value,
            vulnerability_level=vuln_res.baseSeverity.value,
            attack_impact_level=impact_rec.impactLevel.value
        )
        latencies["coreCalculationMs"] = round((time.perf_counter() - t0_calc) * 1000, 3)

        # 6. Continuous Risk State & Trend Detection
        t0_state = time.perf_counter()
        state, _ = risk_state_engine.record_risk_observation(
            device_id=device_id,
            risk_score=calc.riskScore,
            prediction_id=prediction_id
        )
        latencies["trendEvaluationMs"] = round((time.perf_counter() - t0_state) * 1000, 3)

        # 7. XAI and Risk Explanation Synthesis
        t0_xai = time.perf_counter()
        is_partial_xai = xai_explanation is None and (top_contributing_features is None or len(top_contributing_features) == 0)
        risk_exp = risk_explanation_engine.generate_risk_explanation(
            risk_id=calc.calculationId,
            prediction_id=prediction_id,
            device_id=device_id,
            threat_probability=threat_probability,
            asset_criticality_level=crit_level.value,
            asset_criticality_weight=crit_score,
            vulnerability_severity_level=vuln_res.baseSeverity.value,
            vulnerability_weight=vuln_res.effectiveScore,
            attack_impact_level=impact_rec.impactLevel.value,
            attack_impact_weight=impact_rec.impactScore,
            risk_score=calc.riskScore,
            xai_threat_explanation=xai_explanation,
            xai_contributing_features=top_contributing_features,
            is_partial_xai=is_partial_xai
        )
        latencies["explanationSynthesisMs"] = round((time.perf_counter() - t0_xai) * 1000, 3)
        latencies["totalPipelineLatencyMs"] = round((time.perf_counter() - t0_total) * 1000, 2)

        # 8. Assemble Final Risk Object
        final_obj = FinalRiskObject(
            riskId=calc.calculationId,
            predictionId=prediction_id,
            deviceId=device_id,
            threatProbability=threat_probability,
            assetCriticality={
                "level": crit_level.value,
                "score": crit_score
            },
            vulnerability={
                "level": vuln_res.baseSeverity.value,
                "score": vuln_res.effectiveScore,
                "status": vuln_res.status.value
            },
            attackImpact={
                "level": impact_rec.impactLevel.value,
                "score": impact_rec.impactScore
            },
            rawRiskScore=calc.rawRiskScore,
            riskScore=calc.riskScore,
            riskLevel=calc.riskLevel.value,
            predictedCategory=predicted_category,
            categoryConfidence=category_confidence,
            topContributingFeatures=top_contributing_features or [],
            explanation=f"{risk_exp.threatExplanation} {risk_exp.riskExplanation}",
            riskTrend=state.riskTrend.value,
            riskEngineVersion="1.0",
            status="CALCULATED",
            explanationStatus="PARTIAL" if is_partial_xai else "GENERATED",
            pipelineLatencyMs=latencies
        )

        self.audit_log.append(final_obj)
        self._persist_record(final_obj)
        return final_obj

    def _persist_record(self, obj: FinalRiskObject):
        existing = []
        if FINAL_RISK_FILE.exists():
            try:
                with open(FINAL_RISK_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(obj.model_dump())
        existing = existing[-100:]
        with open(FINAL_RISK_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.audit_log.clear()
        if FINAL_RISK_FILE.exists():
            try:
                FINAL_RISK_FILE.unlink()
            except Exception:
                pass

master_risk_orchestrator = MasterRiskOrchestrator()