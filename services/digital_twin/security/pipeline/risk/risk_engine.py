from typing import Dict, Any, List, Optional
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.security.pipeline.detection.detection_models import DetectionResult, DetectionSeverityEnum
from services.digital_twin.security.pipeline.risk.risk_models import (
    RiskAssessment, RiskLevelEnum, ContributingFactor
)

class RiskScoringEngine:
    """Computes contextual, explainable risk assessments from detections and Digital Twin posture."""

    SEVERITY_WEIGHTS = {
        DetectionSeverityEnum.CRITICAL: 1.0,
        DetectionSeverityEnum.HIGH: 0.85,
        DetectionSeverityEnum.MEDIUM: 0.65,
        DetectionSeverityEnum.LOW: 0.40,
        DetectionSeverityEnum.INFO: 0.10
    }

    ZONE_MULTIPLIERS = {
        "EXTERNAL": 1.5,
        "DMZ": 1.3,
        "INTERNAL": 1.0
    }

    def assess_risk(self, detection: DetectionResult) -> RiskAssessment:
        factors: List[ContributingFactor] = []
        target_id = detection.targetDevice
        src_id = detection.sourceDevice

        # 1. Calculate Likelihood
        confidence = detection.confidence
        sev_weight = self.SEVERITY_WEIGHTS.get(detection.severity, 0.5)

        persistence_bonus = 0.0
        if detection.features.get("connectionCount", 0) >= 5 or detection.features.get("portAttemptCount", 0) >= 5:
            persistence_bonus = 0.10
            factors.append(ContributingFactor(
                category="LIKELIHOOD",
                factor="Threat Persistence",
                weightEffect="+0.10",
                description="Repeated/persistent connection attempts observed across window"
            ))

        likelihood = min(1.0, round((confidence * 0.7) + (sev_weight * 0.3) + persistence_bonus, 2))
        factors.append(ContributingFactor(
            category="LIKELIHOOD",
            factor=f"Detection Confidence ({confidence}) & Severity ({detection.severity.value})",
            weightEffect=f"L={likelihood:.2f}",
            description=f"Base detection confidence of {confidence:.2f} calibrated with {detection.severity.value} severity"
        ))

        # 2. Calculate Impact from Digital Twin Context
        # Target device lookup
        target_dev = None
        if hasattr(device_registry, "getDevice"):
            target_dev = device_registry.getDevice(target_id)
        elif hasattr(device_registry, "_devices"):
            target_dev = device_registry._devices.get(target_id)

        # Asset Criticality
        base_criticality = 2.0  # Default MEDIUM
        dev_type = getattr(target_dev, "type", "SERVER") if target_dev else "SERVER"
        dev_type_str = dev_type.value if hasattr(dev_type, "value") else str(dev_type).upper()

        if "DATABASE" in dev_type_str or "DB" in target_id.upper():
            base_criticality = 4.0
            factors.append(ContributingFactor(
                category="ASSET",
                factor="Critical Asset Tier",
                weightEffect="Base Impact: 4.0",
                description=f"Target '{target_id}' houses critical data repository"
            ))
        elif "SERVER" in dev_type_str or "WEB" in target_id.upper():
            base_criticality = 3.0
            factors.append(ContributingFactor(
                category="ASSET",
                factor="High Value Server",
                weightEffect="Base Impact: 3.0",
                description=f"Target '{target_id}' operates as public/internal production service"
            ))
        else:
            base_criticality = 1.5
            factors.append(ContributingFactor(
                category="ASSET",
                factor="Standard Client Workstation",
                weightEffect="Base Impact: 1.5",
                description=f"Target '{target_id}' is a standard client device"
            ))

        # Network Zone Exposure Multiplier
        zone_str = "INTERNAL"
        if target_dev and hasattr(target_dev, "networkZone"):
            z = getattr(target_dev, "networkZone")
            zone_str = z.value if hasattr(z, "value") else str(z).upper()

        exposure_mult = self.ZONE_MULTIPLIERS.get(zone_str, 1.0)
        if exposure_mult > 1.0:
            factors.append(ContributingFactor(
                category="IMPACT",
                factor=f"Network Zone Exposure ({zone_str})",
                weightEffect=f"Multiplier: {exposure_mult}x",
                description=f"Target located in boundary zone '{zone_str}' with public/inbound exposure"
            ))

        # Vulnerability Multiplier
        vuln_penalty = 0.0
        try:
            if hasattr(security_state_engine, "getVulnerabilitySummary"):
                summary = security_state_engine.getVulnerabilitySummary(target_id)
                if getattr(summary, "openVulnerabilities", 0) > 0:
                    vuln_penalty = 2.0
                    factors.append(ContributingFactor(
                        category="VULNERABILITY",
                        factor="Unpatched Vulnerability Present",
                        weightEffect="+2.0 Impact",
                        description=f"Target '{target_id}' has unmitigated CVEs in security state engine"
                    ))
        except Exception:
            pass

        # Harm Potential based on Threat Type & Detection Severity
        harm_penalty = 0.0
        det_type = detection.detectionType.value
        
        # Add severity impact bonus
        if detection.severity == DetectionSeverityEnum.CRITICAL:
            harm_penalty += 2.0
            factors.append(ContributingFactor(
                category="IMPACT",
                factor="Critical Severity Detection",
                weightEffect="+2.0 Impact",
                description="Detection tagged as CRITICAL severity"
            ))
        elif detection.severity == DetectionSeverityEnum.HIGH:
            harm_penalty += 1.0

        if det_type in ("OUTBOUND_VOLUME_ANOMALY", "IDS_SIGNATURE_MATCH"):
            harm_penalty += 2.5
            factors.append(ContributingFactor(
                category="IMPACT",
                factor=f"Severe Threat Potential ({det_type})",
                weightEffect="+2.5 Impact",
                description="Threat pattern indicates data exfiltration or explicit exploit execution"
            ))
        elif det_type in ("TRAFFIC_SPIKE", "AUTHENTICATION_ANOMALY", "BEACONING_PATTERN"):
            harm_penalty += 2.0
            factors.append(ContributingFactor(
                category="IMPACT",
                factor=f"Service Disruption Potential ({det_type})",
                weightEffect="+2.0 Impact",
                description="Threat pattern indicates volumetric saturation or credential exhaustion"
            ))

        raw_impact = (base_criticality * exposure_mult) + vuln_penalty + harm_penalty
        impact = min(10.0, round(raw_impact, 2))

        # 3. Compute Composite Score
        if not detection.detected:
            score = 1.0
            level = RiskLevelEnum.LOW
            explanation = "Traffic operates within normal parameters; minimal risk."
        else:
            raw_score = likelihood * impact * 10.0
            score = min(100.0, round(raw_score, 1))

            if score >= 75.0:
                level = RiskLevelEnum.CRITICAL
            elif score >= 50.0:
                level = RiskLevelEnum.HIGH
            elif score >= 25.0:
                level = RiskLevelEnum.MEDIUM
            else:
                level = RiskLevelEnum.LOW

            explanation = (
                f"Risk Level assessed as {level.value} (Score: {score}/100). "
                f"Derived from {likelihood:.2f} likelihood and {impact:.2f}/10 impact. "
                f"Key drivers: {'; '.join(f.factor for f in factors[:3])}."
            )

        return RiskAssessment(
            detectionId=detection.detectionId,
            targetDevice=target_id,
            sourceDevice=src_id,
            score=score,
            level=level,
            likelihood=likelihood,
            impact=impact,
            contributingFactors=factors,
            explanation=explanation,
            metadata={"detectionType": det_type, "severity": detection.severity.value}
        )

risk_scoring_engine = RiskScoringEngine()