from typing import Dict, List, Optional, Any, Union
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
    """Core state engine maintaining comprehensive device states, telemetry, and transition history."""

    def __init__(self):
        self._device_states: Dict[str, ComprehensiveDeviceStateModel] = {}
        self._history: List[StateTransitionAuditRecord] = []

    def _ensure_device_exists(self, device_id: str, auto_provision: bool = False):
        dev = device_registry.getDevice(device_id)
        if not dev:
            if auto_provision:
                from packages.shared_types.src.network_device import NetworkDeviceModel
                device_registry._devices[device_id] = NetworkDeviceModel(
                    id=device_id,
                    name=device_id,
                    hostname=device_id
                )
            else:
                raise DeviceNotFoundError(f"Device not found in registry: {device_id}")

    def _get_or_init_state(self, device_id: str, auto_provision: bool = False) -> ComprehensiveDeviceStateModel:
        self._ensure_device_exists(device_id, auto_provision=auto_provision)
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

    def updateOperationalState(self, dev_id: str, state_str: Any, reason: str = "Manual status update") -> str:
        try:
            if isinstance(state_str, OperationalStatusEnum):
                enum_val = state_str
            else:
                try:
                    enum_val = OperationalStatusEnum[str(state_str).upper()]
                except (KeyError, AttributeError, ValueError):
                    try:
                        enum_val = OperationalStatusEnum(str(state_str))
                    except ValueError:
                        enum_val = list(OperationalStatusEnum)[0]
        except Exception:
            enum_val = list(OperationalStatusEnum)[0]

        curr = self._get_or_init_state(dev_id, auto_provision=False)
        prev = curr.operationalState.value if hasattr(curr.operationalState, "value") else str(curr.operationalState)
        curr.operationalState = enum_val
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

        dev = device_registry.getDevice(dev_id)
        if dev:
            dev.currentState = enum_val.value if hasattr(enum_val, "value") else str(enum_val)
            device_registry.updateDevice(dev)

        self.recordStateHistory(dev_id, "operational", prev, enum_val.value if hasattr(enum_val, "value") else str(enum_val), reason=reason)
        return enum_val.value if hasattr(enum_val, "value") else str(enum_val)

    def update_operational_state(
        self,
        device: Any,
        cpu_pct: float = 0.0,
        mem_pct: float = 0.0,
        pps: float = 0.0,
        bps: float = 0.0,
        status: str = "HEALTHY",
        **kwargs
    ):
        dev_id = getattr(device, "id", getattr(device, "device_id", str(device)))
        self._ensure_device_exists(dev_id, auto_provision=True)

        target_status = status or kwargs.get("state", "HEALTHY")
        curr_state = self.updateOperationalState(dev_id, target_status, reason="Telemetry update")

        perf_model = PerformanceStateModel(
            cpuUsagePct=float(cpu_pct),
            memoryUsagePct=float(mem_pct)
        )
        self.updatePerformanceState(dev_id, perf_model, reason="Telemetry update")

        net_model = NetworkTelemetryStateModel(
            packetsPerSecond=float(pps),
            bytesPerSecond=float(bps)
        )
        self.updateNetworkState(dev_id, net_model, reason="Telemetry update")

        return curr_state

    def updatePerformanceState(
        self,
        device_id: str,
        performance: PerformanceStateModel,
        reason: str = "Performance metrics update"
    ) -> ComprehensiveDeviceStateModel:
        curr = self._get_or_init_state(device_id, auto_provision=False)
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
        curr = self._get_or_init_state(device_id, auto_provision=False)
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
        curr = self._get_or_init_state(device_id, auto_provision=False)
        prev = [p.model_dump() for p in curr.ports]
        curr.ports = ports
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

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
        curr = self._get_or_init_state(device_id, auto_provision=False)
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
        curr = self._get_or_init_state(device_id, auto_provision=False)
        prev = curr.security.model_dump()
        curr.security = security
        curr.lastUpdated = datetime.now(timezone.utc).isoformat()

        dev = device_registry.getDevice(device_id)
        if dev:
            dev.securityState = security.status.value if hasattr(security.status, "value") else str(security.status)
            dev.riskScore = security.compositeRiskScore
            device_registry.updateDevice(dev)

        self.recordStateHistory(device_id, "security", prev, security.model_dump(), reason=reason)
        return curr

    def update_security_state(
        self,
        device: Any,
        new_state: str,
        trigger: str = "MANUAL",
        reason: str = "Security state change"
    ):
        dev_id = getattr(device, "id", getattr(device, "device_id", str(device)))
        self._ensure_device_exists(dev_id, auto_provision=True)
        curr = self._get_or_init_state(dev_id, auto_provision=True)

        try:
            cond = SecurityConditionEnum(new_state)
        except Exception:
            cond = SecurityConditionEnum.NORMAL

        threat_ids = (
            getattr(curr.security, "activeThreatIds", None) or
            getattr(curr.security, "active_threat_ids", None) or
            getattr(curr.security, "threat_ids", None) or
            []
        )
        risk_val = getattr(curr.security, "compositeRiskScore", getattr(curr.security, "composite_risk_score", 0.0))
        try:
            sec_block = SecurityStateBlockModel(
                status=cond,
                compositeRiskScore=risk_val,
                activeThreatIds=threat_ids
            )
        except Exception:
            sec_block = SecurityStateBlockModel(
                status=cond,
                composite_risk_score=risk_val,
                active_threat_ids=threat_ids
            )
        self.updateSecurityState(dev_id, sec_block, reason=reason)

        from packages.shared_types.src.state import StateTransitionRecord
        return StateTransitionRecord(
            transition_id=f"TRANS-{datetime.now(timezone.utc).timestamp()}",
            device_id=dev_id,
            previous_state=str(getattr(curr.security.status, "value", curr.security.status)),
            new_state=new_state,
            trigger=trigger,
            trigger_source=trigger,
            risk_score=float(risk_val),
            reason=reason
        )

    def updateDeviceState(self, state: ComprehensiveDeviceStateModel, reason: str = "Full state ingest") -> ComprehensiveDeviceStateModel:
        self._ensure_device_exists(state.deviceId, auto_provision=False)
        curr = self._get_or_init_state(state.deviceId, auto_provision=False)
        prev = curr.model_dump()
        state.lastUpdated = datetime.now(timezone.utc).isoformat()
        self._device_states[state.deviceId] = state

        dev = device_registry.getDevice(state.deviceId)
        if dev:
            dev.currentState = state.operationalState.value if hasattr(state.operationalState, "value") else str(state.operationalState)
            dev.securityState = state.security.status.value if hasattr(state.security.status, "value") else str(state.security.status)
            dev.riskScore = state.security.compositeRiskScore
            dev.ports = sorted(list(set(p.port for p in state.ports if p.state == "OPEN")))
            dev.services = sorted(list(set(s.name for s in state.services if s.status == "RUNNING")))
            device_registry.updateDevice(dev)

        self.recordStateHistory(state.deviceId, "full_state", prev, state.model_dump(), reason=reason)
        return state

    def getDeviceState(self, device_id: str) -> Optional[ComprehensiveDeviceStateModel]:
        self._ensure_device_exists(device_id, auto_provision=False)
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