import json
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from packages.database.src.db_connection import db_manager

class SocIntelligenceRepository:
    """Data Access Layer for Alerts, Incidents, Predictions, XAI, Risk, and Attack Paths."""

    # ==================== ALERTS ====================

    @staticmethod
    async def create_or_update_alert(
        alert_id: str,
        source: str,
        destination: str,
        event_type: str,
        affected_device_id: str,
        severity: str = "MEDIUM",
        detection_source: str = "SURICATA",
        detection_type: str = "SIGNATURE",
        confidence: float = 1.0,
        risk_score: float = 50.0,
        risk_level: str = "MEDIUM",
        protocol: str = "TCP",
        port: Optional[int] = None,
        status: str = "NEW",
        evidence: Optional[str] = None,
        incident_id: Optional[str] = None,
        security_event_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.alert.upsert(
            where={"alertId": alert_id},
            data={
                "create": {
                    "alertId": alert_id,
                    "timestamp": ts,
                    "source": source,
                    "destination": destination,
                    "protocol": protocol.upper(),
                    "port": port,
                    "eventType": event_type,
                    "severity": severity.upper(),
                    "detectionSource": detection_source,
                    "detectionType": detection_type,
                    "confidence": float(confidence),
                    "riskScore": float(risk_score),
                    "riskLevel": risk_level.upper(),
                    "affectedDeviceId": affected_device_id,
                    "status": status,
                    "evidence": evidence,
                    "incidentId": incident_id,
                    "securityEventId": security_event_id
                },
                "update": {
                    "severity": severity.upper(),
                    "riskScore": float(risk_score),
                    "riskLevel": risk_level.upper(),
                    "status": status,
                    "evidence": evidence,
                    "incidentId": incident_id
                }
            }
        )

    @staticmethod
    async def get_alert(alert_id: str) -> Optional[Any]:
        prisma = db_manager.client
        return await prisma.alert.find_unique(
            where={"alertId": alert_id},
            include={
                "affectedDevice": True,
                "incident": True,
                "predictions": {"include": {"xaiExplanation": True}}
            }
        )

    # ==================== PREDICTIONS & TEMPORAL ====================

    @staticmethod
    async def record_prediction(
        prediction_id: str,
        device_id: str,
        threat_probability: float,
        threat_class: str,
        predicted_category: str,
        category_confidence: float,
        model_name: str,
        model_version: str,
        risk_score: float = 0.0,
        risk_level: str = "MEDIUM",
        source: Optional[str] = None,
        destination: Optional[str] = None,
        feature_version: str = "v1.0",
        evidence: Optional[str] = None,
        prediction_status: str = "ACTIVE",
        alert_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.prediction.upsert(
            where={"predictionId": prediction_id},
            data={
                "create": {
                    "predictionId": prediction_id,
                    "timestamp": ts,
                    "deviceId": device_id,
                    "source": source,
                    "destination": destination,
                    "threatProbability": float(threat_probability),
                    "threatClass": threat_class,
                    "predictedCategory": predicted_category,
                    "categoryConfidence": float(category_confidence),
                    "riskScore": float(risk_score),
                    "riskLevel": risk_level,
                    "modelName": model_name,
                    "modelVersion": model_version,
                    "featureVersion": feature_version,
                    "evidence": evidence,
                    "predictionStatus": prediction_status,
                    "alertId": alert_id,
                    "incidentId": incident_id
                },
                "update": {
                    "threatProbability": float(threat_probability),
                    "riskScore": float(risk_score),
                    "predictionStatus": prediction_status
                }
            }
        )

    @staticmethod
    async def record_temporal_prediction(
        prediction_id: str,
        device_id: str,
        current_threat_probability: float,
        future_threat_probability: float,
        lead_time: float,
        impact_stage: str,
        warning_status: str = "EARLY_WARNING",
        prediction_horizon: str = "30s",
        model_name: str = "GRU-Temporal-V1",
        model_version: str = "v2.1.0",
        feature_version: str = "v1.0",
        timestamp: Optional[datetime] = None
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.temporalprediction.upsert(
            where={"predictionId": prediction_id},
            data={
                "create": {
                    "predictionId": prediction_id,
                    "timestamp": ts,
                    "deviceId": device_id,
                    "currentThreatProbability": float(current_threat_probability),
                    "futureThreatProbability": float(future_threat_probability),
                    "predictionHorizon": prediction_horizon,
                    "leadTime": float(lead_time),
                    "impactStage": impact_stage,
                    "warningStatus": warning_status,
                    "modelName": model_name,
                    "modelVersion": model_version,
                    "featureVersion": feature_version
                },
                "update": {
                    "currentThreatProbability": float(current_threat_probability),
                    "futureThreatProbability": float(future_threat_probability),
                    "leadTime": float(lead_time),
                    "warningStatus": warning_status
                }
            }
        )

    # ==================== XAI EXPLANATIONS ====================

    @staticmethod
    async def record_xai_explanation(
        prediction_id: str,
        model_name: str,
        model_version: str,
        base_value: float,
        prediction_probability: float,
        feature_values: Dict[str, Any],
        feature_importance: Dict[str, float],
        shap_contributions: Dict[str, float],
        human_explanation: str,
        explanation_type: str = "TreeSHAP"
    ) -> Any:
        prisma = db_manager.client

        return await prisma.xaiexplanation.upsert(
            where={"predictionId": prediction_id},
            data={
                "create": {
                    "predictionId": prediction_id,
                    "modelName": model_name,
                    "modelVersion": model_version,
                    "baseValue": float(base_value),
                    "predictionProbability": float(prediction_probability),
                    "featureValues": json.dumps(feature_values),
                    "featureImportance": json.dumps(feature_importance),
                    "shapContributions": json.dumps(shap_contributions),
                    "humanExplanation": human_explanation,
                    "explanationType": explanation_type
                },
                "update": {
                    "baseValue": float(base_value),
                    "predictionProbability": float(prediction_probability),
                    "humanExplanation": human_explanation
                }
            }
        )

    # ==================== RISK ASSESSMENTS ====================

    @staticmethod
    async def record_risk_assessment(
        device_id: str,
        threat_probability: float,
        asset_criticality: float,
        vulnerability_factor: float,
        attack_impact: float,
        source: str = "CANONICAL_ENGINE",
        incident_id: Optional[str] = None
    ) -> Any:
        prisma = db_manager.client
        # Canonical formula: Risk = P * C * V * I (scaled to 100)
        risk_score = round(threat_probability * asset_criticality * vulnerability_factor * attack_impact * 100.0, 2)

        if risk_score >= 80.0:
            level = "CRITICAL"
        elif risk_score >= 60.0:
            level = "HIGH"
        elif risk_score >= 35.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        return await prisma.riskassessment.create(
            data={
                "deviceId": device_id,
                "threatProbability": float(threat_probability),
                "assetCriticality": float(asset_criticality),
                "vulnerabilityFactor": float(vulnerability_factor),
                "attackImpact": float(attack_impact),
                "riskScore": float(risk_score),
                "riskLevel": level,
                "source": source,
                "incidentId": incident_id
            }
        )

    # ==================== ATTACK PATHS ====================

    @staticmethod
    async def record_attack_path(
        attack_path_id: str,
        source_device_id: str,
        destination_device_id: str,
        path: List[str],
        risk_score: float,
        vulnerabilities: Optional[List[str]] = None,
        exposure: str = "INTERNAL",
        reachability: str = "POSSIBLE",
        status: str = "POSSIBLE",
        evidence: Optional[str] = None,
        incident_id: Optional[str] = None
    ) -> Any:
        prisma = db_manager.client

        return await prisma.attackpath.upsert(
            where={"attackPathId": attack_path_id},
            data={
                "create": {
                    "attackPathId": attack_path_id,
                    "sourceDeviceId": source_device_id,
                    "destinationDeviceId": destination_device_id,
                    "path": path,
                    "riskScore": float(risk_score),
                    "vulnerabilities": vulnerabilities or [],
                    "exposure": exposure,
                    "reachability": reachability,
                    "status": status,
                    "evidence": evidence,
                    "incidentId": incident_id
                },
                "update": {
                    "path": path,
                    "riskScore": float(risk_score),
                    "status": status,
                    "reachability": reachability,
                    "evidence": evidence,
                    "incidentId": incident_id
                }
            }
        )

    # ==================== INCIDENTS & INVESTIGATION CHAIN ====================

    @staticmethod
    async def create_or_update_incident(
        incident_id: str,
        title: str,
        severity: str = "HIGH",
        status: str = "OPEN",
        description: Optional[str] = None,
        assigned_operator: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.incident.upsert(
            where={"incidentId": incident_id},
            data={
                "create": {
                    "incidentId": incident_id,
                    "title": title,
                    "severity": severity.upper(),
                    "status": status,
                    "description": description,
                    "assignedOperator": assigned_operator,
                    "createdAt": ts
                },
                "update": {
                    "title": title,
                    "severity": severity.upper(),
                    "status": status,
                    "description": description,
                    "assignedOperator": assigned_operator
                }
            }
        )

    @staticmethod
    async def get_investigation_chain(incident_id: str) -> Optional[Any]:
        """Retrieves the complete closed-loop investigation story from PostgreSQL."""
        prisma = db_manager.client
        return await prisma.incident.find_unique(
            where={"incidentId": incident_id},
            include={
                "alerts": {
                    "include": {
                        "affectedDevice": True,
                        "predictions": {
                            "include": {
                                "xaiExplanation": True
                            }
                        }
                    }
                },
                "predictions": {
                    "include": {
                        "xaiExplanation": True
                    }
                },
                "riskAssessments": True,
                "attackPaths": True
            }
        )

soc_intelligence_repo = SocIntelligenceRepository()