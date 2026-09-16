from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType, DeviceStatePayload, ConnectionStatePayload
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.models.response import ResponseExecutionRecord
from security.response.validation.response_validator import ResponseSafetyValidator
from security.response.audit.response_audit import response_audit_ledger

class ResponseSimulator:
    """Executes safe automated response simulation against the Digital Twin without touching physical networks."""

    def __init__(self):
        self.active_responses: Dict[str, ResponseExecutionRecord] = {}

    def generate_recommendation_from_intelligence(
        self,
        device_id: str,
        risk_score: float,
        alert_id: str,
        prediction_id: str,
        category: str = "LATERAL_MOVEMENT",
        explanation: str = "Observed suspicious traversal attempt."
    ) -> ResponseRecommendation:
        """Determines optimal defensive action based on risk thresholds and threat classification."""
        if risk_score >= 80.0 or category in ("LATERAL_MOVEMENT", "DATA_EXFILTRATION"):
            action = ResponseActionType.ISOLATE_DEVICE
            reason = f"High severity risk ({risk_score:.1f}) and critical threat {category} require immediate isolation."
        elif risk_score >= 60.0:
            action = ResponseActionType.BLOCK_CONNECTION
            reason = f"Elevated risk ({risk_score:.1f}) requires severing active pivot connections."
        elif risk_score >= 40.0:
            action = ResponseActionType.INCREASE_SECURITY_LEVEL
            reason = f"Moderate risk ({risk_score:.1f}) requires heightened monitoring."
        else:
            action = ResponseActionType.MARK_DEVICE_AT_RISK
            reason = f"Baseline anomaly detected; flagged for active telemetry inspection."

        return ResponseRecommendation(
            actionType=action,
            targetDeviceId=device_id,
            confidenceScore=0.94,
            riskScore=risk_score,
            reason=reason,
            triggeringAlertId=alert_id,
            triggeringPredictionId=prediction_id,
            xaiExplanationSnippet=explanation
        )

    async def execute_simulated_response(
        self,
        recommendation: ResponseRecommendation,
        execution_mode: ExecutionModeEnum = ExecutionModeEnum.SIMULATION,
        operator: str = "SOC_AUTOMATION_PLAYBOOK"
    ) -> ResponseExecutionRecord:
        """Validates safety constraints, mutates the Digital Twin, records audit, and streams to WebSocket."""
        did = recommendation.targetDeviceId
        prev_state = attack_path_graph.nodes[did].securityState if did in attack_path_graph.nodes else "NORMAL"
        
        # Target state determination
        if recommendation.actionType == ResponseActionType.ISOLATE_DEVICE:
            new_state = "ISOLATED"
        elif recommendation.actionType == ResponseActionType.QUARANTINE_ENDPOINT:
            new_state = "QUARANTINED"
        elif recommendation.actionType == ResponseActionType.INCREASE_SECURITY_LEVEL:
            new_state = "MONITORED"
        elif recommendation.actionType == ResponseActionType.MARK_DEVICE_AT_RISK:
            new_state = "AT_RISK"
        else:
            new_state = prev_state

        record = ResponseExecutionRecord(
            recommendationId=recommendation.recommendationId,
            actionType=recommendation.actionType,
            affectedDevice=did,
            affectedLink=recommendation.targetLinkId,
            affectedService=recommendation.targetService,
            reason=recommendation.reason,
            triggeringAlert=recommendation.triggeringAlertId,
            triggeringPrediction=recommendation.triggeringPredictionId,
            riskScore=recommendation.riskScore,
            previousState=prev_state,
            newState=new_state,
            operator=operator,
            executionMode=execution_mode,
            status=ResponseStatusEnum.PENDING
        )

        # 1. Safety Validation
        is_valid, val_reason = ResponseSafetyValidator.validate_execution_request(record)
        if not is_valid:
            record.status = ResponseStatusEnum.REJECTED
            record.resultSummary = f"Rejected by safety policy: {val_reason}"
            audit_entry = response_audit_ledger.record_entry(
                response_id=record.responseId,
                operator=operator,
                action_type=record.actionType.value,
                target_device=did,
                previous_state=prev_state,
                new_state=prev_state,
                execution_mode=execution_mode.value,
                validation_result=val_reason,
                success=False,
                details={"rejectionReason": val_reason}
            )
            record.auditEntryId = audit_entry.auditId
            self.active_responses[record.responseId] = record
            return record

        # 2. Simulation Execution
        record.status = ResponseStatusEnum.SIMULATING
        
        # Mutate Canonical Twin State
        if recommendation.actionType in (ResponseActionType.ISOLATE_DEVICE, ResponseActionType.QUARANTINE_ENDPOINT):
            twin_graph_synchronizer.isolate_device(did)
            if did in attack_path_graph.nodes:
                attack_path_graph.nodes[did].securityState = new_state
            # Synchronize 3D visual projection
            device_3d_renderer_engine.sync_devices_from_twin()
        elif recommendation.actionType == ResponseActionType.BLOCK_CONNECTION and recommendation.targetLinkId:
            if recommendation.targetLinkId in link_3d_renderer_engine.link_registry:
                link_3d_renderer_engine.link_registry[recommendation.targetLinkId].linkState = "BLOCKED"
        else:
            if did in attack_path_graph.nodes:
                attack_path_graph.nodes[did].securityState = new_state
            device_3d_renderer_engine.sync_devices_from_twin()

        record.status = ResponseStatusEnum.APPLIED_TO_TWIN

        # 3. Create Audit Ledger Entry
        audit_entry = response_audit_ledger.record_entry(
            response_id=record.responseId,
            operator=operator,
            action_type=record.actionType.value,
            target_device=did,
            previous_state=prev_state,
            new_state=new_state,
            execution_mode=execution_mode.value,
            validation_result=val_reason,
            success=True,
            details={"riskScore": record.riskScore, "action": record.actionType.value}
        )
        record.auditEntryId = audit_entry.auditId
        record.status = ResponseStatusEnum.COMPLETED
        record.resultSummary = f"Successfully simulated {record.actionType.value} on {did}. Twin state mutated to {new_state}."

        # 4. Stream to Universal Real-Time Store & WebSocket
        dev_payload = DeviceStatePayload(
            deviceId=did,
            previousState=prev_state,
            newState=new_state,
            reason=record.reason,
            quarantineEnforced=(new_state in ("ISOLATED", "QUARANTINED"))
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
            payload=dev_payload.model_dump(),
            device_id=did
        )
        realtime_store_engine.apply_event_envelope(env)
        await websocket_connection_manager.broadcast_envelope(env)

        self.active_responses[record.responseId] = record
        return record

response_simulator = ResponseSimulator()