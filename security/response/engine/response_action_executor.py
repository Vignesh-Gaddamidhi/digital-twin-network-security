from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType, DeviceStatePayload, ConnectionStatePayload
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum
from security.response.models.response import CanonicalResponseContract, ResponseResultRecord
from security.response.validation.response_validator import ResponseSafetyValidator
from security.response.audit.response_audit import response_audit_ledger

class SecurityPostureLevelEnum(str, Enum):
    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    LOCKDOWN_SIMULATION = "LOCKDOWN_SIMULATION"

class ActionExecutionOutput(BaseModel):
    actionType: ResponseActionType
    targetDeviceId: str
    previousState: str
    newState: str
    success: bool
    details: Dict[str, Any] = Field(default_factory=dict)
    message: str

class ResponseActionExecutor:
    """Dispatches and executes every supported defensive response action on the Digital Twin."""

    def __init__(self):
        self.device_services: Dict[str, Dict[str, Any]] = {
            "WEB-01": {"HTTP": {"port": 80, "protocol": "TCP", "status": "RUNNING"}, "HTTPS": {"port": 443, "protocol": "TCP", "status": "RUNNING"}, "SSH": {"port": 22, "protocol": "TCP", "status": "RUNNING"}},
            "DB-01": {"MYSQL": {"port": 3306, "protocol": "TCP", "status": "RUNNING"}, "SSH": {"port": 22, "protocol": "TCP", "status": "RUNNING"}},
            "CLIENT-01": {"RDP": {"port": 3389, "protocol": "TCP", "status": "RUNNING"}},
            "DNS-SERVER-01": {"DNS": {"port": 53, "protocol": "UDP", "status": "RUNNING"}}
        }
        self.device_postures: Dict[str, SecurityPostureLevelEnum] = {}

    def execute_isolate_device(self, device_id: str) -> ActionExecutionOutput:
        node = attack_path_graph.nodes.get(device_id)
        if not node:
            return ActionExecutionOutput(
                actionType=ResponseActionType.ISOLATE_DEVICE, targetDeviceId=device_id,
                previousState="UNKNOWN", newState="UNKNOWN", success=False, message=f"Device {device_id} does not exist"
            )
        prev_state = node.securityState
        
        # 1. Mutate synchronizer store & graph node
        twin_graph_synchronizer.isolate_device(device_id)
        if device_id in attack_path_graph.nodes:
            attack_path_graph.nodes[device_id].securityState = "ISOLATED"

        # 2. Block all incident links in 3D registry
        blocked_links = []
        for lid, link in link_3d_renderer_engine.link_registry.items():
            if link.sourceDeviceId == device_id or link.destinationDeviceId == device_id:
                link.status = "BLOCKED"
                link.trafficRateBps = 0.0
                blocked_links.append(lid)

        # 3. Synchronize 3D projection and enforce graph node state
        device_3d_renderer_engine.sync_devices_from_twin()
        if device_id in attack_path_graph.nodes:
            attack_path_graph.nodes[device_id].securityState = "ISOLATED"
        if device_id in device_3d_renderer_engine.device_mesh_registry:
            device_3d_renderer_engine.device_mesh_registry[device_id].selectionState = "ISOLATED" 

        return ActionExecutionOutput(
            actionType=ResponseActionType.ISOLATE_DEVICE,
            targetDeviceId=device_id,
            previousState=prev_state,
            newState="ISOLATED",
            success=True,
            details={"blockedConnections": blocked_links, "interfaceStatus": "RESTRICTED"},
            message=f"Device {device_id} isolated; {len(blocked_links)} incident links severed in Digital Twin."
        )

    def execute_block_connection(
        self,
        source_device: str,
        destination_device: str,
        link_id: Optional[str] = None
    ) -> ActionExecutionOutput:
        target_lid = link_id
        if not target_lid:
            for lid, link in link_3d_renderer_engine.link_registry.items():
                if (link.sourceDeviceId == source_device and link.destinationDeviceId == destination_device) or \
                   (link.sourceDeviceId == destination_device and link.destinationDeviceId == source_device):
                    target_lid = lid
                    break

        if not target_lid or target_lid not in link_3d_renderer_engine.link_registry:
            return ActionExecutionOutput(
                actionType=ResponseActionType.BLOCK_CONNECTION, targetDeviceId=source_device,
                previousState="ACTIVE", newState="ACTIVE", success=False,
                message=f"No connection path found between {source_device} and {destination_device}"
            )

        link_entry = link_3d_renderer_engine.link_registry[target_lid]
        prev_st = link_entry.status
        link_entry.status = "BLOCKED"
        link_entry.trafficRateBps = 0.0

        return ActionExecutionOutput(
            actionType=ResponseActionType.BLOCK_CONNECTION,
            targetDeviceId=source_device,
            previousState=prev_st,
            newState="BLOCKED",
            success=True,
            details={"linkId": target_lid, "sourceDevice": source_device, "destinationDevice": destination_device, "protocol": "TCP"},
            message=f"Connection {target_lid} between {source_device} and {destination_device} marked BLOCKED."
        )

    def execute_disable_service(self, device_id: str, service_name: str) -> ActionExecutionOutput:
        if device_id not in self.device_services:
            return ActionExecutionOutput(
                actionType=ResponseActionType.DISABLE_SERVICE, targetDeviceId=device_id,
                previousState="UNKNOWN", newState="UNKNOWN", success=False, message=f"Device {device_id} has no registered services"
            )

        services = self.device_services[device_id]
        svc_key = service_name.upper()
        if svc_key not in services:
            return ActionExecutionOutput(
                actionType=ResponseActionType.DISABLE_SERVICE, targetDeviceId=device_id,
                previousState="UNKNOWN", newState="UNKNOWN", success=False, message=f"Service {service_name} not found on {device_id}"
            )

        svc = services[svc_key]
        prev_status = svc["status"]
        svc["status"] = "DISABLED"

        # Update node open ports on graph
        node = attack_path_graph.nodes.get(device_id)
        if node:
            if hasattr(node, "ports") and svc["port"] in node.ports:
                node.ports.remove(svc["port"])
            elif hasattr(node, "openPorts") and svc["port"] in node.openPorts:
                node.openPorts.remove(svc["port"])

        return ActionExecutionOutput(
            actionType=ResponseActionType.DISABLE_SERVICE,
            targetDeviceId=device_id,
            previousState=prev_status,
            newState="DISABLED",
            success=True,
            details={"serviceName": svc_key, "port": svc["port"], "protocol": svc["protocol"]},
            message=f"Service {svc_key} (Port {svc['port']}) disabled on {device_id}."
        )

    def execute_quarantine_endpoint(self, device_id: str) -> ActionExecutionOutput:
        node = attack_path_graph.nodes.get(device_id)
        if not node:
            return ActionExecutionOutput(
                actionType=ResponseActionType.QUARANTINE_ENDPOINT, targetDeviceId=device_id,
                previousState="UNKNOWN", newState="UNKNOWN", success=False, message=f"Device {device_id} does not exist"
            )

        prev_state = node.securityState
        twin_graph_synchronizer.isolate_device(device_id)
        node.securityState = "QUARANTINED"
        device_3d_renderer_engine.sync_devices_from_twin()

        return ActionExecutionOutput(
            actionType=ResponseActionType.QUARANTINE_ENDPOINT,
            targetDeviceId=device_id,
            previousState=prev_state,
            newState="QUARANTINED",
            success=True,
            details={"endpointQuarantine": True, "restrictedVLAN": "QUARANTINE_ZONE"},
            message=f"Endpoint {device_id} moved to simulated QUARANTINED state."
        )

    def execute_increase_security_level(
        self,
        device_id: str,
        target_posture: SecurityPostureLevelEnum = SecurityPostureLevelEnum.ELEVATED
    ) -> ActionExecutionOutput:
        node = attack_path_graph.nodes.get(device_id)
        if not node:
            return ActionExecutionOutput(
                actionType=ResponseActionType.INCREASE_SECURITY_LEVEL, targetDeviceId=device_id,
                previousState="UNKNOWN", newState="UNKNOWN", success=False, message=f"Device {device_id} does not exist"
            )

        prev_posture = self.device_postures.get(device_id, SecurityPostureLevelEnum.STANDARD)
        self.device_postures[device_id] = target_posture
        prev_node_st = node.securityState
        node.securityState = "MONITORED"
        device_3d_renderer_engine.sync_devices_from_twin()

        return ActionExecutionOutput(
            actionType=ResponseActionType.INCREASE_SECURITY_LEVEL,
            targetDeviceId=device_id,
            previousState=prev_posture.value,
            newState=target_posture.value,
            success=True,
            details={"nodeSecurityState": "MONITORED", "idsSamplingRate": "2x"},
            message=f"Defensive security posture elevated on {device_id}: {prev_posture.value} -> {target_posture.value}."
        )

    def execute_mark_device_at_risk(self, device_id: str) -> ActionExecutionOutput:
        node = attack_path_graph.nodes.get(device_id)
        if not node:
            return ActionExecutionOutput(
                actionType=ResponseActionType.MARK_DEVICE_AT_RISK, targetDeviceId=device_id,
                previousState="UNKNOWN", newState="UNKNOWN", success=False, message=f"Device {device_id} does not exist"
            )

        prev_st = node.securityState
        # Ensure that AT_RISK does not equal COMPROMISED
        node.securityState = "AT_RISK"
        device_3d_renderer_engine.sync_devices_from_twin()

        return ActionExecutionOutput(
            actionType=ResponseActionType.MARK_DEVICE_AT_RISK,
            targetDeviceId=device_id,
            previousState=prev_st,
            newState="AT_RISK",
            success=True,
            details={"isCompromised": False, "threatBeaconActive": True},
            message=f"Device {device_id} tagged as AT_RISK (Prediction != Compromised)."
        )

    async def dispatch_canonical_response_action(
        self,
        contract: CanonicalResponseContract
    ) -> ActionExecutionOutput:
        """Executes the specific response action and records immutable audit trail and WebSocket broadcast."""
        # 1. Safety validation
        is_valid, reason = ResponseSafetyValidator.validate_canonical_response(contract)
        if not is_valid:
            return ActionExecutionOutput(
                actionType=contract.action,
                targetDeviceId=contract.affectedDevice,
                previousState=contract.previousState,
                newState=contract.previousState,
                success=False,
                message=f"Safety validation failed: {reason}"
            )

        # 2. Dispatch to specific action handler
        did = contract.affectedDevice
        act = contract.action

        if act == ResponseActionType.ISOLATE_DEVICE:
            res = self.execute_isolate_device(did)
        elif act == ResponseActionType.BLOCK_CONNECTION:
            src = contract.triggeringAlert.alertId  # fallback or use link metadata
            res = self.execute_block_connection("CLIENT-01", did)
        elif act == ResponseActionType.DISABLE_SERVICE:
            svc_name = "HTTP"
            res = self.execute_disable_service(did, svc_name)
        elif act == ResponseActionType.QUARANTINE_ENDPOINT:
            res = self.execute_quarantine_endpoint(did)
        elif act == ResponseActionType.INCREASE_SECURITY_LEVEL:
            res = self.execute_increase_security_level(did, SecurityPostureLevelEnum.ELEVATED)
        elif act == ResponseActionType.MARK_DEVICE_AT_RISK:
            res = self.execute_mark_device_at_risk(did)
        else:
            res = ActionExecutionOutput(
                actionType=act, targetDeviceId=did, previousState=contract.previousState,
                newState=contract.previousState, success=False, message=f"Unsupported action {act}"
            )

        if res.success:
            # Broadcast state update to WebSocket
            dev_payload = DeviceStatePayload(
                deviceId=did,
                previousState=res.previousState,
                newState=res.newState,
                reason=contract.reason,
                quarantineEnforced=(res.newState in ("ISOLATED", "QUARANTINED"))
            )
            env = realtime_event_manager.build_envelope(
                event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
                payload=dev_payload.model_dump(),
                device_id=did
            )
            realtime_store_engine.apply_event_envelope(env)
            await websocket_connection_manager.broadcast_envelope(env)

            # Record audit entry with complete intelligence context
            details = dict(res.details)
            details["triggeringAlert"] = getattr(contract.triggeringAlert, "alertId", "ALT-AUTO")
            details["triggeringPrediction"] = getattr(contract.triggeringPrediction, "predictionId", "PRD-AUTO")
            details["riskScore"] = getattr(contract.riskAssessment, "riskScore", 75.0)
            details["reason"] = contract.reason

            audit_entry = response_audit_ledger.record_entry(
                response_id=contract.responseId,
                operator=contract.operator,
                action_type=contract.action.value,
                target_device=did,
                previous_state=res.previousState,
                new_state=res.newState,
                execution_mode=contract.mode.value,
                validation_result="APPROVED_SIMULATION",
                success=True,
                details=details
            )
            contract.auditEntryId = audit_entry.auditId
            contract.executionStatus = ResponseStatusEnum.COMPLETED

        return res

response_action_executor = ResponseActionExecutor()