from typing import Dict, Tuple, List, Optional
from packages.shared_types.src.attack_severity import (
    SeverityLevelEnum, RiskLevelEnum, AssetCriticalityEnum,
    ScenarioClassificationResult, RiskAssessmentReport
)
from packages.shared_types.src.attack_scenario import AttackScenarioModel, AttackScenarioCategoryEnum
from services.digital_twin.core.devices.network_device_registry import device_registry

class SeverityEngine:
    """Classifies attack scenarios and performs quantitative Likelihood x Impact risk assessments."""

    BASELINE_SEVERITY_MAP: Dict[AttackScenarioCategoryEnum, SeverityLevelEnum] = {
        AttackScenarioCategoryEnum.PORT_SCAN: SeverityLevelEnum.MEDIUM,
        AttackScenarioCategoryEnum.BRUTE_FORCE: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.DOS: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.SUSPICIOUS_DNS: SeverityLevelEnum.MEDIUM,
        AttackScenarioCategoryEnum.BEACONING: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.LATERAL_MOVEMENT: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.DATA_EXFILTRATION: SeverityLevelEnum.CRITICAL,
    }

    BASELINE_LIKELIHOOD_MAP: Dict[AttackScenarioCategoryEnum, float] = {
        AttackScenarioCategoryEnum.PORT_SCAN: 0.85,
        AttackScenarioCategoryEnum.BRUTE_FORCE: 0.70,
        AttackScenarioCategoryEnum.DOS: 0.75,
        AttackScenarioCategoryEnum.SUSPICIOUS_DNS: 0.60,
        AttackScenarioCategoryEnum.BEACONING: 0.75,
        AttackScenarioCategoryEnum.LATERAL_MOVEMENT: 0.70,
        AttackScenarioCategoryEnum.DATA_EXFILTRATION: 0.80,
    }

    BASELINE_IMPACT_MAP: Dict[AttackScenarioCategoryEnum, float] = {
        AttackScenarioCategoryEnum.PORT_SCAN: 4.0,
        AttackScenarioCategoryEnum.BRUTE_FORCE: 7.5,
        AttackScenarioCategoryEnum.DOS: 8.0,
        AttackScenarioCategoryEnum.SUSPICIOUS_DNS: 5.5,
        AttackScenarioCategoryEnum.BEACONING: 7.0,
        AttackScenarioCategoryEnum.LATERAL_MOVEMENT: 8.5,
        AttackScenarioCategoryEnum.DATA_EXFILTRATION: 10.0,
    }

    @staticmethod
    def get_asset_criticality(device_id: str) -> AssetCriticalityEnum:
        dev = device_registry.getDevice(device_id)
        if not dev:
            return AssetCriticalityEnum.MEDIUM

        dtype = dev.type.value if hasattr(dev.type, "value") else str(dev.type)
        zone = dev.networkZone.value if hasattr(dev.networkZone, "value") else str(dev.networkZone)

        if dtype in ("DATABASE", "VAULT") or "db" in device_id.lower():
            return AssetCriticalityEnum.CRITICAL
        if dtype in ("SERVER", "DNS_SERVER") or zone == "DMZ":
            return AssetCriticalityEnum.HIGH
        if zone == "INTERNAL" and dtype == "CLIENT":
            return AssetCriticalityEnum.MEDIUM
        return AssetCriticalityEnum.LOW

    def classify_scenario(self, scenario: AttackScenarioModel) -> ScenarioClassificationResult:
        base_sev = self.BASELINE_SEVERITY_MAP.get(scenario.category, SeverityLevelEnum.MEDIUM)
        crit = self.get_asset_criticality(scenario.targetDevice)

        is_exfil = (scenario.category == AttackScenarioCategoryEnum.DATA_EXFILTRATION)
        is_lateral = (scenario.category == AttackScenarioCategoryEnum.LATERAL_MOVEMENT)

        desc = f"Simulated {scenario.category.value} pattern with initial severity {base_sev.value} targeting {scenario.targetDevice} ({crit.value} criticality)."

        return ScenarioClassificationResult(
            scenarioId=scenario.scenarioId,
            category=scenario.category.value,
            initialSeverity=base_sev,
            targetDevice=scenario.targetDevice,
            targetCriticality=crit,
            isExfiltrationVector=is_exfil,
            isLateralMovementVector=is_lateral,
            description=desc
        )

    def assess_risk(self, scenario: AttackScenarioModel) -> RiskAssessmentReport:
        classification = self.classify_scenario(scenario)
        cat = scenario.category

        base_likelihood = self.BASELINE_LIKELIHOOD_MAP.get(cat, 0.50)
        base_impact = self.BASELINE_IMPACT_MAP.get(cat, 5.0)

        mitigating = []
        aggravating = []

        # Asset criticality impact modulation
        crit = classification.targetCriticality
        if crit == AssetCriticalityEnum.CRITICAL:
            base_impact = 10.0
            base_likelihood = min(1.0, base_likelihood * 1.15)
            aggravating.append(f"Target '{scenario.targetDevice}' is a CRITICAL asset")
        elif crit == AssetCriticalityEnum.LOW:
            base_impact = max(1.0, base_impact * 0.80)
            mitigating.append(f"Target '{scenario.targetDevice}' is an isolated LOW criticality endpoint")

        # Intensity multiplier adjustments
        intensity = scenario.trafficPattern.intensityMultiplier
        if intensity > 2.0:
            base_likelihood = min(1.0, base_likelihood * 1.1)
            aggravating.append(f"High traffic intensity multiplier ({intensity}x)")
        elif intensity < 0.5:
            base_likelihood = max(0.1, base_likelihood * 0.85)
            mitigating.append("Low and slow traffic pattern decreases immediate detection likelihood")

        # Calculate Final Risk Score: (Likelihood * Impact) * 10
        raw_score = round(base_likelihood * base_impact * 10.0, 2)
        risk_score = max(0.0, min(100.0, raw_score))

        # Classify Risk Level
        if risk_score >= 75.0:
            rlevel = RiskLevelEnum.CRITICAL
        elif risk_score >= 50.0:
            rlevel = RiskLevelEnum.HIGH
        elif risk_score >= 25.0:
            rlevel = RiskLevelEnum.MEDIUM
        else:
            rlevel = RiskLevelEnum.LOW

        return RiskAssessmentReport(
            scenarioId=scenario.scenarioId,
            targetDevice=scenario.targetDevice,
            baseSeverity=classification.initialSeverity,
            likelihoodScore=round(base_likelihood, 2),
            impactScore=round(base_impact, 2),
            riskScore=risk_score,
            riskLevel=rlevel,
            mitigatingFactors=mitigating,
            aggravatingFactors=aggravating
        )

severity_engine = SeverityEngine()