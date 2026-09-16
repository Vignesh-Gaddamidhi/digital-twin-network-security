import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select, delete
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import (
    Alert, Incident, Prediction, TemporalPrediction,
    XaiExplanation, RiskAssessment, AttackPath,
    AlertStatusEnum, IncidentStatusEnum, ThreatWarningStatusEnum, AttackPathStatusEnum
)

class SocIntelligenceRepository:
    """SQLAlchemy 2.0 DAL for Alerts, Incidents, Predictions, XAI, Risk, and Attack Paths."""

    # ==================== INCIDENTS ====================

    @staticmethod
    async def create_or_update_incident(
        incident_id: str,
        title: str,
        severity: str = "HIGH",
        status: str = "OPEN",
        description: Optional[str] = None,
        assigned_operator: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Incident:
        now = timestamp or datetime.now(timezone.utc)
        status_enum = IncidentStatusEnum(status.upper()) if isinstance(status, str) else status

        async with db_manager.session() as sess:
            res = await sess.execute(select(Incident).where(Incident.incident_id == incident_id))
            inc = res.scalar_one_or_none()

            if not inc:
                inc = Incident(
                    incident_id=incident_id,
                    title=title,
                    severity=severity.upper(),
                    status=status_enum,
                    description=description,
                    assigned_operator=assigned_operator,
                    created_at=now,
                    updated_at=now
                )
                sess.add(inc)
            else:
                inc.title = title
                inc.severity = severity.upper()
                inc.status = status_enum
                inc.description = description
                inc.assigned_operator = assigned_operator
                inc.updated_at = now

            await sess.flush()
            return inc

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
    ) -> Alert:
        now = timestamp or datetime.now(timezone.utc)
        status_enum = AlertStatusEnum(status.upper()) if isinstance(status, str) else status

        async with db_manager.session() as sess:
            res = await sess.execute(select(Alert).where(Alert.alert_id == alert_id))
            alt = res.scalar_one_or_none()

            if not alt:
                alt = Alert(
                    alert_id=alert_id,
                    timestamp=now,
                    source=source,
                    destination=destination,
                    protocol=protocol.upper(),
                    port=port,
                    event_type=event_type,
                    severity=severity.upper(),
                    detection_source=detection_source,
                    detection_type=detection_type,
                    confidence=float(confidence),
                    risk_score=float(risk_score),
                    risk_level=risk_level.upper(),
                    affected_device_id=affected_device_id,
                    status=status_enum,
                    evidence=evidence,
                    incident_id=incident_id,
                    security_event_id=security_event_id,
                    created_at=now,
                    updated_at=now
                )
                sess.add(alt)
            else:
                alt.severity = severity.upper()
                alt.risk_score = float(risk_score)
                alt.risk_level = risk_level.upper()
                alt.status = status_enum
                alt.evidence = evidence
                alt.incident_id = incident_id
                alt.updated_at = now

            await sess.flush()
            return alt

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
    ) -> Prediction:
        now = timestamp or datetime.now(timezone.utc)

        async with db_manager.session() as sess:
            res = await sess.execute(select(Prediction).where(Prediction.prediction_id == prediction_id))
            pred = res.scalar_one_or_none()

            if not pred:
                pred = Prediction(
                    prediction_id=prediction_id,
                    timestamp=now,
                    device_id=device_id,
                    source=source,
                    destination=destination,
                    threat_probability=float(threat_probability),
                    threat_class=threat_class,
                    predicted_category=predicted_category,
                    category_confidence=float(category_confidence),
                    risk_score=float(risk_score),
                    risk_level=risk_level,
                    model_name=model_name,
                    model_version=model_version,
                    feature_version=feature_version,
                    evidence=evidence,
                    prediction_status=prediction_status,
                    alert_id=alert_id,
                    incident_id=incident_id
                )
                sess.add(pred)
            else:
                pred.threat_probability = float(threat_probability)
                pred.risk_score = float(risk_score)
                pred.prediction_status = prediction_status

            await sess.flush()
            return pred

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
    ) -> TemporalPrediction:
        now = timestamp or datetime.now(timezone.utc)
        warn_enum = ThreatWarningStatusEnum(warning_status.upper()) if isinstance(warning_status, str) else warning_status

        async with db_manager.session() as sess:
            res = await sess.execute(select(TemporalPrediction).where(TemporalPrediction.prediction_id == prediction_id))
            t_pred = res.scalar_one_or_none()

            if not t_pred:
                t_pred = TemporalPrediction(
                    prediction_id=prediction_id,
                    timestamp=now,
                    device_id=device_id,
                    current_threat_probability=float(current_threat_probability),
                    future_threat_probability=float(future_threat_probability),
                    prediction_horizon=prediction_horizon,
                    lead_time=float(lead_time),
                    impact_stage=impact_stage,
                    warning_status=warn_enum,
                    model_name=model_name,
                    model_version=model_version,
                    feature_version=feature_version
                )
                sess.add(t_pred)
            else:
                t_pred.current_threat_probability = float(current_threat_probability)
                t_pred.future_threat_probability = float(future_threat_probability)
                t_pred.lead_time = float(lead_time)
                t_pred.warning_status = warn_enum

            await sess.flush()
            return t_pred

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
    ) -> XaiExplanation:
        async with db_manager.session() as sess:
            res = await sess.execute(select(XaiExplanation).where(XaiExplanation.prediction_id == prediction_id))
            xai = res.scalar_one_or_none()

            if not xai:
                xai = XaiExplanation(
                    explanation_id=str(uuid.uuid4()),
                    prediction_id=prediction_id,
                    timestamp=datetime.now(timezone.utc),
                    model_name=model_name,
                    model_version=model_version,
                    base_value=float(base_value),
                    prediction_probability=float(prediction_probability),
                    feature_values=feature_values,
                    feature_importance=feature_importance,
                    shap_contributions=shap_contributions,
                    human_explanation=human_explanation,
                    explanation_type=explanation_type
                )
                sess.add(xai)
            else:
                xai.base_value = float(base_value)
                xai.prediction_probability = float(prediction_probability)
                xai.human_explanation = human_explanation
                xai.shap_contributions = shap_contributions

            await sess.flush()
            return xai

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
    ) -> RiskAssessment:
        risk_score = round(threat_probability * asset_criticality * vulnerability_factor * attack_impact * 100.0, 2)
        if risk_score >= 80.0:
            level = "CRITICAL"
        elif risk_score >= 60.0:
            level = "HIGH"
        elif risk_score >= 35.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        async with db_manager.session() as sess:
            risk = RiskAssessment(
                risk_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                device_id=device_id,
                threat_probability=float(threat_probability),
                asset_criticality=float(asset_criticality),
                vulnerability_factor=float(vulnerability_factor),
                attack_impact=float(attack_impact),
                risk_score=float(risk_score),
                risk_level=level,
                source=source,
                incident_id=incident_id
            )
            sess.add(risk)
            await sess.flush()
            return risk

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
    ) -> AttackPath:
        status_enum = AttackPathStatusEnum(status.upper()) if isinstance(status, str) else status

        async with db_manager.session() as sess:
            res = await sess.execute(select(AttackPath).where(AttackPath.attack_path_id == attack_path_id))
            ap = res.scalar_one_or_none()

            if not ap:
                ap = AttackPath(
                    attack_path_id=attack_path_id,
                    timestamp=datetime.now(timezone.utc),
                    source_device_id=source_device_id,
                    destination_device_id=destination_device_id,
                    path=list(path),
                    risk_score=float(risk_score),
                    vulnerabilities=list(vulnerabilities or []),
                    exposure=exposure,
                    reachability=reachability,
                    status=status_enum,
                    evidence=evidence,
                    incident_id=incident_id
                )
                sess.add(ap)
            else:
                ap.path = list(path)
                ap.risk_score = float(risk_score)
                ap.status = status_enum
                ap.reachability = reachability
                ap.evidence = evidence
                ap.incident_id = incident_id

            await sess.flush()
            return ap

    # ==================== INVESTIGATION CHAIN ====================

    @staticmethod
    async def get_investigation_chain(incident_id: str) -> Optional[Incident]:
        """Loads complete 7-stage closed-loop investigation story with eager joins."""
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Incident)
                .where(Incident.incident_id == incident_id)
                .options(
                    selectinload(Incident.alerts).selectinload(Alert.affected_device),
                    selectinload(Incident.alerts).selectinload(Alert.predictions).selectinload(Prediction.xai_explanation),
                    selectinload(Incident.predictions).selectinload(Prediction.xai_explanation),
                    selectinload(Incident.risk_assessments),
                    selectinload(Incident.attack_paths)
                )
            )
            return res.scalar_one_or_none()

soc_intelligence_repo = SocIntelligenceRepository()