import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[4]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk"
RISK_FILE = RISK_ARTIFACTS_DIR / "risk_assessments.json"

from services.digital_twin.ml.risk.risk_models import (
    DeviceCriticalityEnum, NetworkExposureEnum, VulnerabilityStatusEnum,
    OperationalRiskLevel, RiskThresholdConfig, PredictionRiskAssessment
)

class PredictionRiskEngine:
    """Combines machine learning threat predictions with operational asset context."""

    CATEGORY_BASE_SEVERITY = {
        "NORMAL": 0.0,
        "PORT_SCAN": 0.40,
        "BEACONING": 0.55,
        "DNS_ANOMALY": 0.60,
        "BRUTE_FORCE_LIKE": 0.70,
        "DOS_LIKE": 0.80,
        "LATERAL_MOVEMENT_LIKE": 0.85,
        "EXFILTRATION_LIKE": 0.95,
        "NETWORK_INTRUSION": 0.75
    }

    CRITICALITY_WEIGHTS = {
        DeviceCriticalityEnum.LOW: 0.30,
        DeviceCriticalityEnum.MEDIUM: 0.60,
        DeviceCriticalityEnum.HIGH: 0.85,
        DeviceCriticalityEnum.MISSION_CRITICAL: 1.00
    }

    EXPOSURE_WEIGHTS = {
        NetworkExposureEnum.INTERNAL_ISOLATED: 0.10,
        NetworkExposureEnum.INTERNAL_ROUTABLE: 0.40,
        NetworkExposureEnum.DMZ: 0.70,
        NetworkExposureEnum.EXTERNAL_FACING: 1.00
    }

    VULNERABILITY_WEIGHTS = {
        VulnerabilityStatusEnum.NONE_KNOWN: 0.00,
        VulnerabilityStatusEnum.PATCHED: 0.20,
        VulnerabilityStatusEnum.MITIGATED: 0.50,
        VulnerabilityStatusEnum.OPEN_UNPATCHED: 1.00
    }

    def __init__(self, thresholds: RiskThresholdConfig = RiskThresholdConfig()):
        self.thresholds = thresholds
        RISK_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        self.history: List[PredictionRiskAssessment] = []

    def assess_risk(
        self,
        prediction_id: str,
        threat_probability: float,
        predicted_category: str,
        category_confidence: float,
        device_criticality: DeviceCriticalityEnum = DeviceCriticalityEnum.MEDIUM,
        network_exposure: NetworkExposureEnum = NetworkExposureEnum.INTERNAL_ROUTABLE,
        vulnerability_status: VulnerabilityStatusEnum = VulnerabilityStatusEnum.NONE_KNOWN,
        observed_anomalies: Optional[List[str]] = None,
        model_version: str = "1.0.0"
    ) -> PredictionRiskAssessment:
        p_threat = max(0.0, min(1.0, float(threat_probability)))
        conf = max(0.0, min(1.0, float(category_confidence)))

        # 1. Likelihood & Impact Components
        cat_sev = self.CATEGORY_BASE_SEVERITY.get(predicted_category.upper(), 0.50)
        crit_w = self.CRITICALITY_WEIGHTS.get(device_criticality, 0.60)
        expo_w = self.EXPOSURE_WEIGHTS.get(network_exposure, 0.40)
        vuln_w = self.VULNERABILITY_WEIGHTS.get(vulnerability_status, 0.00)

        likelihood = p_threat * conf
        impact = cat_sev * crit_w
        env_multiplier = 1.0 + (0.40 * expo_w) + (0.40 * vuln_w)

        # Baseline benign shortcut
        if p_threat < 0.15 and predicted_category.upper() == "NORMAL":
            raw_score = round(p_threat * 100.0 * 0.2, 1)
        else:
            raw_score = round(((0.45 * likelihood) + (0.55 * impact)) * 100.0 * env_multiplier, 1)

        score = max(0.0, min(100.0, raw_score))

        # 2. Map to Configurable Risk Level
        if score < self.thresholds.lowThreshold:
            level = OperationalRiskLevel.LOW
        elif score < self.thresholds.mediumThreshold:
            level = OperationalRiskLevel.MEDIUM
        elif score < self.thresholds.highThreshold:
            level = OperationalRiskLevel.HIGH
        else:
            level = OperationalRiskLevel.CRITICAL

        # 3. Formulate Explainable Contributing Factors
        factors = []
        if p_threat >= 0.70:
            factors.append(f"Elevated threat probability ({round(p_threat * 100, 1)}%)")
        if conf >= 0.80:
            factors.append(f"High category confidence ({round(conf * 100, 1)}%)")
        if network_exposure in (NetworkExposureEnum.DMZ, NetworkExposureEnum.EXTERNAL_FACING):
            factors.append(f"Heightened asset exposure ({network_exposure.value})")
        if device_criticality in (DeviceCriticalityEnum.HIGH, DeviceCriticalityEnum.MISSION_CRITICAL):
            factors.append(f"High-impact asset criticality ({device_criticality.value})")
        if vulnerability_status == VulnerabilityStatusEnum.OPEN_UNPATCHED:
            factors.append("Active open unpatched vulnerability present on target device")
        if observed_anomalies:
            factors.extend(observed_anomalies)

        if not factors:
            factors.append("Routine baseline parameters observed within normal tolerances")

        explanation = (
            f"Assigned {level.value} risk (score: {score:.1f}) synthesized from {predicted_category} "
            f"prediction on {device_criticality.value} asset with {network_exposure.value} perimeter exposure."
        )

        assessment = PredictionRiskAssessment(
            predictionId=prediction_id,
            threatProbability=p_threat,
            threatProbabilityFormatted=f"{round(p_threat * 100, 1)}%",
            predictedCategory=predicted_category,
            categoryConfidence=conf,
            categoryConfidenceFormatted=f"{round(conf * 100, 1)}%",
            riskScore=score,
            riskLevel=level,
            contributingFactors=factors,
            explanation=explanation,
            modelVersion=model_version,
            contextSnapshot={
                "deviceCriticality": device_criticality.value,
                "networkExposure": network_exposure.value,
                "vulnerabilityStatus": vulnerability_status.value,
                "environmentalMultiplier": round(env_multiplier, 3)
            }
        )

        self.history.append(assessment)
        self._persist_assessments([assessment])
        return assessment

    def _persist_assessments(self, records: List[PredictionRiskAssessment]):
        existing = []
        if RISK_FILE.exists():
            try:
                with open(RISK_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.extend([r.model_dump() for r in records])
        existing = existing[-200:]
        with open(RISK_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        if RISK_FILE.exists():
            try:
                RISK_FILE.unlink()
            except Exception:
                pass

prediction_risk_engine = PredictionRiskEngine()