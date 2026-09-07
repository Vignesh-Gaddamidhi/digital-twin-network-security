from typing import Dict, Any, List
from services.twin_engine.src.core.twin_state import twin_engine, DeviceEntity

class DynamicRiskEngine:
    """Calculates mathematical risk scores across Digital Twin network nodes."""

    @staticmethod
    def calculate_node_risk(node: DeviceEntity, threat_probability: float = 0.2) -> Dict[str, Any]:
        criticality = node.criticality

        # 1. Evaluate Max CVSS across OPEN vulnerabilities only
        open_vulns = [v for v in node.vulnerabilities if v.status == "OPEN"]
        if open_vulns:
            max_cvss = max(v.cvss_score for v in open_vulns)
            primary_cve = max(open_vulns, key=lambda v: v.cvss_score).cve_id
        else:
            max_cvss = 1.0
            primary_cve = "NONE"

        # 2. Derive Exposure Factor from Node Attack Surface
        exposure_factor = node.attack_surface.exposure_multiplier

        # 3. Mitigation Factor (Firewall rule coverage deduction)
        mitigation_factor = min(len(node.firewall_rules) * 0.1, 0.4)

        # 4. Risk Calculation Formula
        base_risk = (criticality * max_cvss) / 10.0
        threat_multiplier = threat_probability * 5.0
        raw_score = base_risk * exposure_factor * threat_multiplier * (1.0 - mitigation_factor)
        composite_score = round(min(max(raw_score * 10.0, 0.0), 100.0), 2)

        # Synchronize score back to node security model
        node.security_state_model.risk_score = composite_score

        # 5. Severity Classification
        if composite_score >= 75.0:
            severity = "CRITICAL"
        elif composite_score >= 50.0:
            severity = "HIGH"
        elif composite_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "node_id": node.id,
            "hostname": node.hostname,
            "composite_risk_score": composite_score,
            "risk_severity": severity,
            "metrics": {
                "criticality": criticality,
                "max_cvss": max_cvss,
                "primary_cve": primary_cve,
                "open_vulns_count": len(open_vulns),
                "exposure_tier": node.attack_surface.exposure_tier,
                "exposure_factor": exposure_factor,
                "threat_probability": threat_probability,
                "mitigation_factor": round(mitigation_factor, 2)
            }
        }

    @classmethod
    def evaluate_entire_topology(cls, ambient_threat_prob: float = 0.2) -> List[Dict[str, Any]]:
        results = []
        for node in twin_engine.node_registry.values():
            results.append(cls.calculate_node_risk(node, threat_probability=ambient_threat_prob))
        results.sort(key=lambda x: x["composite_risk_score"], reverse=True)
        return results

risk_engine = DynamicRiskEngine()