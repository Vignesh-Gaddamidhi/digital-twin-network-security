from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType, DeviceStatePayload
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.models.response import (
    CanonicalResponseContract, TriggeringAlertReference, TriggeringPredictionReference,
    ResponseRiskBreakdown, ResponseResultRecord, generate_canonical_response_id
)
from security.response.engine.state_transition_engine import state_transition_engine
from security.response.validation.response_validator import ResponseSafetyValidator
from security.response.audit.response_audit import response_audit_ledger

class ResponseSimulator:
    """Executes safe automated response simulation against the Digital Twin without touching physical networks."""

    def __init__(self):
        self.active_responses: Dict[str, CanonicalResponseContract] = {}

    def generate_recommendation_from_intelligence(
        self,
        device_id: str,
        risk_score: float,
        alert_id: str,
        prediction_id: str,
        category: str = "LATERAL_MOVEMENT",
        explanation: str = "Observed suspicious traversal attempt."
    ) -> ResponseRecommendation:
        if risk_score >= 80.0 or category in ("LATERAL_MOVEMENT", "DATA_EXFILTRATION"):
            action = ResponseActionType.ISOLATE_DEVICE
            reason = f"Critical risk score ({risk_score:.1f}) and severe threat '{category}' mandate device containment."
        elif risk_score >= 60.0:
            action = ResponseActionType.BLOCK_CONNECTION
            reason = f"Elevated risk ({risk_score:.1f}) requires isolating inbound pivot paths."
        elif risk_score >= 40.0:
            action = ResponseActionType.INCREASE_SECURITY_LEVEL
            reason = f"Moderate risk ({risk_score:.1f}) requires elevating telemetry inspection level."
        else:
            action = ResponseActionType.MARK_DEVICE_AT_RISK
            reason = f"Anomaly detected; host tagged as at-risk."

        level = RiskLevelTier.CRITICAL if risk_score >= 80 else RiskLevelTier.HIGH if risk_score >= 60 else RiskLevelTier.MEDIUM
        return ResponseRecommendation(
            alertId=alert_id,
            predictionId=prediction_id,
            deviceId=device_id,
            riskScore=risk_score,
            riskLevel=level,
            recommendedAction=action,
            reason=reason,
            evidence=[explanation],
            confidence=0.95,
            simulationRequired=True
        )

    def create_canonical_response_contract(
        self,
        recommendation: ResponseRecommendation,
        operator: str = "AUTOMATED_SIMULATION",
        mode: ExecutionModeEnum = ExecutionModeEnum.SIMULATION
    ) -> CanonicalResponseContract:
        did = recommendation.deviceId or getattr(recommendation, "targetDeviceId", None) or "WEB-01"
        action = getattr(recommendation, "recommendedAction", getattr(recommendation, "actionType", ResponseActionType.ISOLATE_DEVICE))
        alert_id = recommendation.alertId or getattr(recommendation, "triggeringAlertId", None) or "ALT-001"
        prediction_id = recommendation.predictionId or getattr(recommendation, "triggeringPredictionId", None) or "PRD-001"

        prev_st = attack_path_graph.nodes[did].securityState if did in attack_path_graph.nodes else "NORMAL"
        _, target_st, _ = state_transition_engine.resolve_target_state(action, prev_st)

        # Risk Breakdown calculation (P * C * V * I = score)
        threat_prob = round(recommendation.riskScore / 80.0, 2)  # calibrated scale
        threat_prob = min(1.0, max(0.1, threat_prob))
        calculated_score = round(threat_prob * 1.0 * 0.8 * 1.0 * 100.0, 1)

        level = RiskLevelTier.LOW
        if calculated_score >= 80.0:
            level = RiskLevelTier.CRITICAL
        elif calculated_score >= 60.0:
            level = RiskLevelTier.HIGH
        elif calculated_score >= 40.0:
            level = RiskLevelTier.MEDIUM

        risk_data = ResponseRiskBreakdown(
            riskScore=calculated_score,
            riskLevel=level,
            threatProbability=threat_prob,
            assetCriticality=1.0,
            vulnerabilityFactor=0.8,
            attackImpact=1.0
        )

        alert_ref = TriggeringAlertReference(
            alertId=alert_id,
            eventType="UNAUTHORIZED_ACCESS",
            severity=RiskLevelTier.CRITICAL if calculated_score >= 80 else RiskLevelTier.HIGH,
            confidence=0.94,
            riskScore=calculated_score
        )

        pred_ref = TriggeringPredictionReference(
            predictionId=prediction_id,
            threatProbability=threat_prob,
            predictedCategory="LATERAL_MOVEMENT",
            categoryConfidence=0.92
        )

        return CanonicalResponseContract(
            responseId=generate_canonical_response_id(),
            action=action,
            reason=recommendation.reason,
            triggeringAlert=alert_ref,
            triggeringPrediction=pred_ref,
            riskAssessment=risk_data,
            affectedDevice=did,
            previousState=prev_st,
            newState=target_st,
            operator=operator,
            mode=mode,
            executionStatus=ResponseStatusEnum.PENDING
        )

    async def execute_simulated_response(
        self,
        recommendation: ResponseRecommendation,
        execution_mode: ExecutionModeEnum = ExecutionModeEnum.SIMULATION,
        operator: str = "AUTOMATED_SIMULATION"
    ) -> CanonicalResponseContract:
        # Build canonical response contract
        contract = self.create_canonical_response_contract(recommendation, operator=operator, mode=execution_mode)

        # 1. Validate canonical response
        is_valid, val_reason = ResponseSafetyValidator.validate_canonical_response(contract)
        if not is_valid:
            contract.executionStatus = ResponseStatusEnum.REJECTED
            contract.result.status = "REJECTED"
            contract.result.message = f"Rejected: {val_reason}"
            contract.result.twinUpdated = False

            audit_entry = response_audit_ledger.record_entry(
                response_id=contract.responseId,
                operator=operator,
                action_type=contract.action.value,
                target_device=contract.affectedDevice,
                previous_state=contract.previousState,
                new_state=contract.previousState,
                execution_mode=execution_mode.value,
                validation_result=val_reason,
                success=False,
                details={"rejectionReason": val_reason}
            )
            contract.auditEntryId = audit_entry.auditId
            self.active_responses[contract.responseId] = contract
            return contract

        # 2. Mutate Canonical Digital Twin
        contract.executionStatus = ResponseStatusEnum.SIMULATING
        did = contract.affectedDevice
        new_st = contract.newState

        affected_conns = []
        if contract.action in (ResponseActionType.ISOLATE_DEVICE, ResponseActionType.QUARANTINE_ENDPOINT):
            twin_graph_synchronizer.isolate_device(did)
            if did in attack_path_graph.nodes:
                attack_path_graph.nodes[did].securityState = new_st
            device_3d_renderer_engine.sync_devices_from_twin()
            affected_conns = [lid for lid, l in link_3d_renderer_engine.link_registry.items() if l.sourceDeviceId == did or l.destinationDeviceId == did]
        elif contract.action == ResponseActionType.BLOCK_CONNECTION and recommendation.targetLinkId:
            if recommendation.targetLinkId in link_3d_renderer_engine.link_registry:
                link_3d_renderer_engine.link_registry[recommendation.targetLinkId].linkState = "BLOCKED"
                affected_conns = [recommendation.targetLinkId]
        else:
            if did in attack_path_graph.nodes:
                attack_path_graph.nodes[did].securityState = new_st
            device_3d_renderer_engine.sync_devices_from_twin()

        # 3. Update Result Record
        contract.result.status = "COMPLETED"
        contract.result.message = f"Successfully executed simulated {contract.action.value} on {did}."
        contract.result.twinUpdated = True
        contract.result.affectedConnections = affected_conns
        contract.executionStatus = ResponseStatusEnum.COMPLETED

        # 4. Record Immutable Audit Ledger
        audit_entry = response_audit_ledger.record_entry(
            response_id=contract.responseId,
            operator=operator,
            action_type=contract.action.value,
            target_device=did,
            previous_state=contract.previousState,
            new_state=new_st,
            execution_mode=execution_mode.value,
            validation_result=val_reason,
            success=True,
            details={"riskScore": contract.riskAssessment.riskScore, "action": contract.action.value}
        )
        contract.auditEntryId = audit_entry.auditId

        # 5. Broadcast to WebSocket and Update Real-time Store
        dev_payload = DeviceStatePayload(
            deviceId=did,
            previousState=contract.previousState,
            newState=new_st,
            reason=contract.reason,
            quarantineEnforced=(new_st in ("ISOLATED", "QUARANTINED"))
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
            payload=dev_payload.model_dump(),
            device_id=did
        )
        realtime_store_engine.apply_event_envelope(env)
        await websocket_connection_manager.broadcast_envelope(env)

        self.active_responses[contract.responseId] = contract
        return contract

response_simulator = ResponseSimulator()