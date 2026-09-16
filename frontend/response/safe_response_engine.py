import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType, DeviceStatePayload
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine
from frontend.response.response_models import (
    ResponseActionType, ExecutionMode, ResponseStatus,
    SimulatedResponseRecord, ResponseRecommendation
)

logger = logging.getLogger("twin.response")

class SafeResponseEngine:
    """Enterprise engine executing safe, simulated automated mitigations without real-world network impact."""

    def __init__(self):
        self.response_ledger: List[SimulatedResponseRecord] = []
        self.active_recommendations: Dict[str, ResponseRecommendation] = {}
        self.max_ledger_size = 500

    def generate_recommendation(
        self,
        device_id: str,
        risk_score: float,
        predicted_category: str = "LATERAL_MOVEMENT"
    ) -> ResponseRecommendation:
        """Determines optimal simulated response playbook based on threat type and risk score."""
        if risk_score >= 80.0:
            action = ResponseActionType.ISOLATE_DEVICE
            reason = f"High-confidence {predicted_category} detected with critical risk ({risk_score}). Immediate node isolation required."
            reduction = 60.0
        elif risk_score >= 60.0:
            action = ResponseActionType.BLOCK_CONNECTION
            reason = f"Suspicious ingress traffic matches {predicted_category}. Recommend blocking ingress edge links."
            reduction = 40.0
        elif risk_score >= 40.0:
            action = ResponseActionType.DISABLE_SERVICE
            reason = f"Vulnerable port exposure exploited. Recommend closing vulnerable application listening port."
            reduction = 25.0
        else:
            action = ResponseActionType.INCREASE_SECURITY_LEVEL
            reason = f"Elevated anomaly score. Escalating device telemetry sampling rate to deep inspection."
            reduction = 10.0

        rec = ResponseRecommendation(
            actionType=action,
            targetDeviceId=device_id,
            suggestedReason=reason,
            projectedRiskReduction=reduction,
            confidenceScore=0.94,
            requiresManualApproval=risk_score < 75.0
        )
        self.active_recommendations[device_id] = rec
        return rec

    async def execute_simulated_response(
        self,
        action_type: ResponseActionType,
        device_id: str,
        triggering_alert_id: str = "ALT-MANUAL-001",
        triggering_prediction_id: str = "PRD-MANUAL-001",
        risk_score: float = 85.0,
        operator: str = "SOC_ANALYST_AUTO",
        reason: Optional[str] = None
    ) -> SimulatedResponseRecord:
        """Applies simulated remediation to Canonical Digital Twin, writes audit log, and streams WebSocket update."""
        if device_id not in attack_path_graph.nodes:
            raise ValueError(f"Device {device_id} not found in Digital Twin graph.")

        node = attack_path_graph.nodes[device_id]
        prev_state = node.securityState
        rollback_info: Dict[str, Any] = {"previousState": prev_state, "previousRisk": node.riskScore}
        execution_result = ""
        new_state = prev_state

        # 1. Execute Playbook Action on Digital Twin
        if action_type in (ResponseActionType.ISOLATE_DEVICE, ResponseActionType.QUARANTINE_ENDPOINT):
            twin_graph_synchronizer.isolate_device(device_id)
            node.securityState = "ISOLATED"
            new_state = "ISOLATED"
            node.riskScore = max(10.0, node.riskScore - 55.0)
            execution_result = f"Device {device_id} air-gapped from all subnet routing edges."

        elif action_type == ResponseActionType.BLOCK_CONNECTION:
            node.securityState = "AT_RISK"
            new_state = "AT_RISK"
            # Sever links connected to target device in 3D scene and graph
            severed_links = []
            for lid, link in list(link_3d_renderer_engine.link_registry.items()):
                if link.sourceDeviceId == device_id or link.destinationDeviceId == device_id:
                    link.status = "BLOCKED"
                    severed_links.append(lid)
            rollback_info["severedLinks"] = severed_links
            execution_result = f"Blocked {len(severed_links)} active network edges connected to {device_id}."

        elif action_type == ResponseActionType.DISABLE_SERVICE:
            node.securityState = "SUSPICIOUS"
            new_state = "SUSPICIOUS"
            node_ports = getattr(node, "ports", getattr(node, "openPorts", []))
            target_port = 80 if 80 in node_ports else (node_ports[0] if node_ports else 443)
            rollback_info["closedPort"] = target_port
            execution_result = f"Closed listener on port {target_port} for host {device_id}."

        elif action_type == ResponseActionType.INCREASE_SECURITY_LEVEL:
            node.securityState = "MONITORED"
            new_state = "MONITORED"
            execution_result = f"Sampling profile for {device_id} increased to Level 3 (Deep NetFlow inspection)."

        elif action_type == ResponseActionType.MARK_DEVICE_AT_RISK:
            node.securityState = "AT_RISK"
            new_state = "AT_RISK"
            execution_result = f"Device {device_id} tagged AT_RISK. Outbound lateral traversals flagged."

        # 2. Synchronize visual and store layers
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()

        # 3. Create Immutable Audit Ledger Entry
        record = SimulatedResponseRecord(
            actionType=action_type,
            reason=reason or f"Mitigation executed: {action_type.value} on {device_id}",
            triggeringAlertId=triggering_alert_id,
            triggeringPredictionId=triggering_prediction_id,
            riskScore=risk_score,
            affectedDeviceId=device_id,
            previousState=prev_state,
            newState=new_state,
            operator=operator,
            mode=ExecutionMode.SIMULATION,
            status=ResponseStatus.EXECUTED,
            result=execution_result,
            rollbackData=rollback_info
        )
        self.response_ledger.insert(0, record)
        if len(self.response_ledger) > self.max_ledger_size:
            self.response_ledger.pop()

        # 4. Broadcast Real-Time WebSocket Event Envelope
        dev_payload = DeviceStatePayload(
            deviceId=device_id,
            previousState=prev_state,
            newState=new_state,
            reason=record.result,
            quarantineEnforced=(new_state == "ISOLATED")
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
            payload=dev_payload.model_dump(),
            device_id=device_id
        )
        realtime_store_engine.apply_event_envelope(env)
        await websocket_connection_manager.broadcast_envelope(env)

        return record

    async def rollback_response(self, response_id: str) -> SimulatedResponseRecord:
        """Reverses a previously executed simulated response, restoring baseline Twin properties."""
        target_record = next((r for r in self.response_ledger if r.responseId == response_id), None)
        if not target_record:
            raise ValueError(f"Response record {response_id} not found in ledger.")

        did = target_record.affectedDeviceId
        if did in attack_path_graph.nodes:
            prev_st = target_record.rollbackData.get("previousState", "NORMAL")
            attack_path_graph.nodes[did].securityState = prev_st
            if "previousRisk" in target_record.rollbackData:
                attack_path_graph.nodes[did].riskScore = target_record.rollbackData["previousRisk"]

        # Restore any severed links
        if "severedLinks" in target_record.rollbackData:
            for lid in target_record.rollbackData["severedLinks"]:
                if lid in link_3d_renderer_engine.link_registry:
                    link_3d_renderer_engine.link_registry[lid].status = "ACTIVE"

        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()

        target_record.status = ResponseStatus.ROLLED_BACK
        target_record.result += " [ROLLED BACK TO BASELINE]"

        # Broadcast state rollback
        dev_payload = DeviceStatePayload(
            deviceId=did,
            previousState=target_record.newState,
            newState=target_record.previousState,
            reason=f"Rollback of {target_record.responseId} executed.",
            quarantineEnforced=False
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
            payload=dev_payload.model_dump(),
            device_id=did
        )
        realtime_store_engine.apply_event_envelope(env)
        await websocket_connection_manager.broadcast_envelope(env)

        return target_record

safe_response_engine = SafeResponseEngine()