from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine
from frontend.topology.three_d_navigation_engine import three_d_navigation_engine
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeEventEnvelope, ThreatTelemetryPayload,
    AlertTelemetryPayload, PredictionTelemetryPayload, RiskTelemetryPayload,
    AttackPathTelemetryPayload, EarlyWarningPayload, DeviceStatePayload
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager

class EarlyWarningStateEnum(str, Enum):
    NO_WARNING = "NO_WARNING"
    WATCH = "WATCH"
    EARLY_WARNING = "EARLY_WARNING"
    HIGH_CONFIDENCE_WARNING = "HIGH_CONFIDENCE_WARNING"
    IMPACT_STAGE = "IMPACT_STAGE"

class LiveThreatRecord(BaseModel):
    threatId: str
    timestamp: str
    sourceDeviceId: str
    targetDeviceId: str
    eventType: str
    severity: RiskLevelTier
    confidenceScore: float
    detectionSource: str

class LiveAlertRecord(BaseModel):
    alertId: str
    timestamp: str
    sourceDevice: str
    destinationDevice: str
    protocol: str = "TCP"
    destinationPort: int = 443
    eventType: str
    severity: RiskLevelTier
    detectionSource: str
    confidence: float
    riskScore: float
    riskLevel: RiskLevelTier
    affectedDevice: str
    status: str = "NEW"

class LivePredictionRecord(BaseModel):
    predictionId: str
    deviceId: str
    currentThreatProbability: float
    futureThreatProbability: float
    predictedCategory: str
    confidenceScore: float
    riskScore: float
    riskLevel: RiskLevelTier
    leadTimeSeconds: int = 45
    warningState: EarlyWarningStateEnum = EarlyWarningStateEnum.WATCH
    xaiExplanations: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class LiveSecurityIntelligenceEngine:
    """Pipelines live security events, ML forecasts, dynamic risk updates, and 3D path illumination."""

    def __init__(self):
        self.threat_store: List[LiveThreatRecord] = []
        self.alert_store: List[LiveAlertRecord] = []
        self.prediction_store: Dict[str, LivePredictionRecord] = {}
        self.max_threats = 200
        self.max_alerts = 200

    async def emit_threat_update(
        self,
        source_device_id: str,
        target_device_id: str,
        event_type: str,
        severity: RiskLevelTier = RiskLevelTier.HIGH,
        confidence: float = 0.92,
        detection_source: str = "Suricata-IDS"
    ) -> RealtimeEventEnvelope:
        threat_id = f"THR-{uuid.uuid4().hex[:6].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()

        record = LiveThreatRecord(
            threatId=threat_id,
            timestamp=now_ts,
            sourceDeviceId=source_device_id,
            targetDeviceId=target_device_id,
            eventType=event_type,
            severity=severity,
            confidenceScore=confidence,
            detectionSource=detection_source
        )
        self.threat_store.append(record)
        if len(self.threat_store) > self.max_threats:
            self.threat_store.pop(0)

        payload = ThreatTelemetryPayload(
            threatId=threat_id,
            sourceDeviceId=source_device_id,
            targetDeviceId=target_device_id,
            eventType=event_type,
            severity=severity,
            confidenceScore=confidence,
            detectionSource=detection_source
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.THREAT_UPDATE,
            payload=payload.model_dump(),
            device_id=target_device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def emit_alert_update(
        self,
        source_device: str,
        destination_device: str,
        event_type: str,
        severity: RiskLevelTier = RiskLevelTier.CRITICAL,
        risk_score: float = 85.5,
        confidence: float = 0.94
    ) -> RealtimeEventEnvelope:
        alert_id = f"ALT-{uuid.uuid4().hex[:6].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()

        record = LiveAlertRecord(
            alertId=alert_id,
            timestamp=now_ts,
            sourceDevice=source_device,
            destinationDevice=destination_device,
            eventType=event_type,
            severity=severity,
            detectionSource="Realtime-Pipeline",
            confidence=confidence,
            riskScore=risk_score,
            riskLevel=severity,
            affectedDevice=destination_device
        )
        self.alert_store.append(record)
        if len(self.alert_store) > self.max_alerts:
            self.alert_store.pop(0)

        payload = AlertTelemetryPayload(
            alertId=alert_id,
            severity=severity,
            sourceDevice=source_device,
            destinationDevice=destination_device,
            eventType=event_type,
            status="NEW",
            riskScore=risk_score
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.ALERT_UPDATE,
            payload=payload.model_dump(),
            device_id=destination_device
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def emit_prediction_update(
        self,
        device_id: str,
        current_prob: float,
        future_prob: float,
        predicted_category: str = "LATERAL_MOVEMENT",
        confidence: float = 0.91,
        risk_score: float = 78.4,
        lead_time_seconds: int = 42,
        warning_state: EarlyWarningStateEnum = EarlyWarningStateEnum.EARLY_WARNING,
        xai_explanations: Optional[List[str]] = None
    ) -> RealtimeEventEnvelope:
        pred_id = f"PRD-{uuid.uuid4().hex[:6].upper()}"
        explanations = xai_explanations or [
            "Connection frequency increased significantly (145 conns/min vs 12 baseline)",
            "Destination diversity changed from baseline (probes touching multiple ports)",
            "Port activity observed on unassigned internal service interfaces"
        ]

        record = LivePredictionRecord(
            predictionId=pred_id,
            deviceId=device_id,
            currentThreatProbability=round(current_prob, 3),
            futureThreatProbability=round(future_prob, 3),
            predictedCategory=predicted_category,
            confidenceScore=round(confidence, 3),
            riskScore=round(risk_score, 1),
            riskLevel=RiskLevelTier.CRITICAL if risk_score >= 80 else RiskLevelTier.HIGH,
            leadTimeSeconds=lead_time_seconds,
            warningState=warning_state,
            xaiExplanations=explanations
        )
        self.prediction_store[device_id] = record

        payload = PredictionTelemetryPayload(
            targetDeviceId=device_id,
            currentThreatProbability=record.currentThreatProbability,
            futureThreatProbability=record.futureThreatProbability,
            predictedCategory=record.predictedCategory,
            confidenceScore=record.confidenceScore,
            topFeatures=explanations
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.PREDICTION_UPDATE,
            payload=payload.model_dump(),
            device_id=device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def emit_early_warning_update(
        self,
        device_id: str,
        lead_time_seconds: int,
        future_prob: float,
        warning_state: EarlyWarningStateEnum
    ) -> RealtimeEventEnvelope:
        payload = EarlyWarningPayload(
            targetDeviceId=device_id,
            leadTimeSeconds=lead_time_seconds,
            futureThreatProbability=round(future_prob, 3),
            warningState=warning_state.value
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.EARLY_WARNING_UPDATE,
            payload=payload.model_dump(),
            device_id=device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def update_device_risk(
        self,
        device_id: str,
        threat_prob: float,
        criticality: float = 1.0,
        vulnerability_factor: float = 0.8,
        impact: float = 1.0
    ) -> RealtimeEventEnvelope:
        """Calculates and streams canonical Risk Engine score: P(threat) * Criticality * Vuln * Impact * 100."""
        composite_score = round(threat_prob * criticality * vulnerability_factor * impact * 100.0, 1)
        composite_score = max(0.0, min(100.0, composite_score))

        level = RiskLevelTier.LOW
        if composite_score >= 80.0:
            level = RiskLevelTier.CRITICAL
        elif composite_score >= 60.0:
            level = RiskLevelTier.HIGH
        elif composite_score >= 40.0:
            level = RiskLevelTier.MEDIUM

        # Update Twin node risk score
        if device_id in attack_path_graph.nodes:
            attack_path_graph.nodes[device_id].riskScore = composite_score

        # Synchronize 3D mesh visual label risk
        if device_id in device_3d_renderer_engine.device_mesh_registry:
            device_3d_renderer_engine.device_mesh_registry[device_id].label.riskScore = composite_score

        payload = RiskTelemetryPayload(
            targetDeviceId=device_id,
            compositeRiskScore=composite_score,
            riskLevel=level,
            threatProbability=threat_prob,
            assetCriticality="CRITICAL" if criticality >= 1.0 else "HIGH",
            vulnerabilityFactor=vulnerability_factor,
            attackImpact=impact
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.RISK_UPDATE,
            payload=payload.model_dump(),
            device_id=device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def trigger_live_attack_path_highlight(
        self,
        path_id: Optional[str] = None
    ) -> RealtimeEventEnvelope:
        """Triggers dynamic 3D attack path highlighting and broadcasts ATTACK_PATH_UPDATE."""
        three_d_navigation_engine.sync_attack_paths()
        if not path_id:
            available_paths = list(three_d_navigation_engine.cached_attack_paths.keys())
            target_path_id = available_paths[0] if available_paths else "PATH-DEFAULT"
        else:
            target_path_id = path_id

        # Mutate 3D visual selection engine
        path_detail = three_d_navigation_engine.select_attack_path_3d(target_path_id)

        chain = path_detail.traversedNodeSequence if path_detail else ["CLIENT-01", "WEB-01", "DB-01"]
        risk_score = path_detail.riskScore if path_detail else 80.4

        payload = AttackPathTelemetryPayload(
            pathId=target_path_id,
            sourceDevice=chain[0],
            targetDevice=chain[-1],
            nodeSequence=chain,
            hopCount=len(chain) - 1,
            riskScore=risk_score,
            riskLevel=RiskLevelTier.CRITICAL if risk_score >= 80 else RiskLevelTier.HIGH,
            reachability="REACHABLE",
            isCompromisedChain=True
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.ATTACK_PATH_UPDATE,
            payload=payload.model_dump(),
            device_id=chain[-1]
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

live_security_engine = LiveSecurityIntelligenceEngine()