from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import copy

from packages.shared_types.src.device_state import (
    ComprehensiveDeviceStateModel, PerformanceStateModel, NetworkTelemetryStateModel,
    PortStateEntry, ServiceRuntimeEntry, SecurityStateBlockModel,
    OperationalStatusEnum, SecurityConditionEnum, VulnerabilityStatusEnum,
    StateTransitionAuditRecord
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class StateEngine:
    """Central engine managing continuous state vectors and immutable state history."""

    def __init__(self):
        self._device_states: Dict[str, ComprehensiveDeviceStateModel] = {}
        self._history: List[StateTransitionAuditRecord] = []

    def _ensure_device_exists(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' does not exist in Device Registry.")

    def _get_or_init_state(self, device_id: str) -> ComprehensiveDeviceStateModel:
        self._ensure_device_exists(device_id)
        if device_id not in self._device_states:
            self._device_states[device_id] = ComprehensiveDeviceStateModel(deviceId=device_id)
        return self._device_states[device_id]

    def recordStateHistory(
        self,
        device_id: str,
        component: str,
        previous_value: Any,
        new_value: Any,
        trigger: str = "TELEMETRY",
        reason: str = "Component update"
    ) -> StateTransitionAuditRecord:
        record = StateTransitionAuditRecord(
            deviceId=device_id,
            component=component,
            previousValue=copy.deepcopy(previous_value),
            newValue=copy.deepcopy(new_value),
            timestamp=datetime.now(timezone.utc).isoformat(),
            triggerSource=trigger,
            reason=reason
        )
        self._history.append(record)
        return record

    def updateOperationalState(
        self,
        device_id: str,
        state: OperationalStatusEnum,
        reason: str = "Operational status change"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id)
        prev = curr.operationalState.value
        curr.operationalState = state
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

        # Update root device currentState
        dev = device_registry.getDevice(device_id)
        if dev:
            dev.currentState = state.value
            device_registry.updateDevice(dev)

        self.recordStateHistory(device_id, "operationalState", prev, state.value, reason=reason)
        return curr

    def updatePerformanceState(
        self,
        device_id: str,
        performance: PerformanceStateModel,
        reason: str = "Performance metrics update"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id)
        prev = curr.performance.model_dump()
        curr.performance = performance
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()
        self.recordStateHistory(device_id, "performance", prev, performance.model_dump(), reason=reason)
        return curr

    def updateNetworkState(
        self,
        device_id: str,
        network: NetworkTelemetryStateModel,
        reason: str = "Network telemetry update"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id)
        prev = curr.network.model_dump()
        curr.network = network
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()
        self.recordStateHistory(device_id, "network", prev, network.model_dump(), reason=reason)
        return curr

    def updatePortState(
        self,
        device_id: str,
        ports: List[PortStateEntry],
        reason: str = "Listening ports refresh"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id)
        prev = [p.model_dump() for p in curr.ports]
        curr.ports = ports
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

        # Sync open ports list with device registry
        dev = device_registry.getDevice(device_id)
        if dev:
            dev.ports = sorted(list(set(p.port for p in ports if p.state == "OPEN")))
            device_registry.updateDevice(dev)

        self.recordStateHistory(device_id, "ports", prev, [p.model_dump() for p in ports], reason=reason)
        return curr

    def updateServiceState(
        self,
        device_id: str,
        services: List[ServiceRuntimeEntry],
        reason: str = "Services refresh"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id)
        prev = [s.model_dump() for s in curr.services]
        curr.services = services
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

        dev = device_registry.getDevice(device_id)
        if dev:
            dev.services = sorted(list(set(s.name for s in services if s.status == "RUNNING")))
            device_registry.updateDevice(dev)

        self.recordStateHistory(device_id, "services", prev, [s.model_dump() for s in services], reason=reason)
        return curr

    def updateSecurityState(
        self,
        device_id: str,
        security: SecurityStateBlockModel,
        reason: str = "Security posture change"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id)
        prev = curr.security.model_dump()
        curr.security = security
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

        dev = device_registry.getDevice(device_id)
        if dev:
            dev.securityState = security.status.value
            dev.riskScore = security.compositeRiskScore
            device_registry.updateDevice(dev)

        self.recordStateHistory(device_id, "security", prev, security.model_dump(), reason=reason)
        return curr

    def updateDeviceState(self, state: ComprehensiveDeviceStateModel, reason: str = "Full state ingest") -> ComprehensiveDeviceStateModel:
        self._ensure_device_exists(state.deviceId)
        curr = self._get_or_init_state(state.deviceId)
        prev = curr.model_dump()
        state.lastUpdated = datetime.now(timezone.utc).isoformat()
        self._device_states[state.deviceId] = state

        # Cascade updates to device registry
        dev = device_registry.getDevice(state.deviceId)
        if dev:
            dev.currentState = state.operationalState.value
            dev.securityState = state.security.status.value
            dev.riskScore = state.security.compositeRiskScore
            dev.ports = sorted(list(set(p.port for p in state.ports if p.state == "OPEN")))
            dev.services = sorted(list(set(s.name for s in state.services if s.status == "RUNNING")))
            device_registry.updateDevice(dev)

        self.recordStateHistory(state.deviceId, "full_state", prev, state.model_dump(), reason=reason)
        return state

    def getDeviceState(self, device_id: str) -> Optional[ComprehensiveDeviceStateModel]:
        self._ensure_device_exists(device_id)
        return self._device_states.get(device_id)

    def getAllDeviceStates(self) -> List[ComprehensiveDeviceStateModel]:
        return list(self._device_states.values())

    def getStateHistory(self, device_id: Optional[str] = None, component: Optional[str] = None) -> List[StateTransitionAuditRecord]:
        results = self._history
        if device_id:
            results = [h for h in results if h.deviceId == device_id]
        if component:
            results = [h for h in results if h.component == component]
        return results

    def clear(self):
        self._device_states.clear()
        self._history.clear()

state_engine = StateEngine()