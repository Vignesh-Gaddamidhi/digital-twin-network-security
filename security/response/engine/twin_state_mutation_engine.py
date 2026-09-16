from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType, ResponseUpdatePayload, DeviceStatePayload
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum
from security.response.models.response import CanonicalResponseContract
from security.response.engine.response_action_executor import response_action_executor

class StateTransitionRecord(BaseModel):
    transitionId: str = Field(default_factory=lambda: f"TRN-{uuid.uuid4().hex[:8].upper()}")
    responseId: str
    deviceId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previousState: str
    newState: str
    action: ResponseActionType
    reason: str
    affectedConnectionsCount: int = 0
    attackPathStatus: str = "BLOCKED"

class TwinStateMutationEngine:
    """Manages transactional state transitions, state history, and attack-path reachability updates."""

    def __init__(self):
        self.transition_history: List[StateTransitionRecord] = []

    async def apply_response_to_twin_and_broadcast(
        self,
        contract: CanonicalResponseContract
    ) -> StateTransitionRecord:
        did = contract.affectedDevice
        node = attack_path_graph.nodes.get(did)
        prev_state = node.securityState if node else contract.previousState

        # 1. Execute simulated action against the Digital Twin
        out = await response_action_executor.dispatch_canonical_response_action(contract)

        # 2. Check if attack path is severed when device is isolated or connection blocked
        affected_conns_count = len(out.details.get("blockedConnections", []))
        path_status = "ACTIVE"

        if contract.action in (ResponseActionType.ISOLATE_DEVICE, ResponseActionType.QUARANTINE_ENDPOINT):
            # Invalidate attack paths touching this device
            for p in realtime_store_engine.attackPaths:
                if did in p.get("nodeSequence", []):
                    p["reachability"] = "BLOCKED"
                    p["status"] = "BLOCKED"
            path_status = "BLOCKED"

        # 3. Create State Transition Record & Append to History
        transition = StateTransitionRecord(
            responseId=contract.responseId,
            deviceId=did,
            previousState=prev_state,
            newState=out.newState,
            action=contract.action,
            reason=contract.reason,
            affectedConnectionsCount=affected_conns_count,
            attackPathStatus=path_status
        )
        self.transition_history.append(transition)

        # 4. Generate and Broadcast Real-Time RESPONSE_UPDATE Event
        payload = ResponseUpdatePayload(
            responseId=contract.responseId,
            action=contract.action.value,
            affectedDevice=did,
            previousState=prev_state,
            newState=out.newState,
            resultStatus="SUCCESS" if out.success else "FAILED",
            mode=contract.mode.value,
            details=out.details
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.RESPONSE_UPDATE,
            payload=payload.model_dump(),
            device_id=did
        )
        realtime_store_engine.apply_event_envelope(env)
        await websocket_connection_manager.broadcast_envelope(env)

        return transition

    def get_history_for_device(self, device_id: str) -> List[StateTransitionRecord]:
        return [t for t in self.transition_history if t.deviceId == device_id]

    def get_latest_transitions(self, limit: int = 50) -> List[StateTransitionRecord]:
        return self.transition_history[-limit:]

twin_state_mutation_engine = TwinStateMutationEngine()