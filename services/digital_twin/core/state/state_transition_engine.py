from typing import Dict, List, Optional, Set
from datetime import datetime, timezone

from packages.shared_types.src.device_state import (
    OperationalStatusEnum, OperationalTransitionRecord
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class InvalidStateTransitionError(ValueError):
    pass

class StateTransitionEngine:
    """Manages deterministic finite-state machine transitions for device operational states."""

    # Valid State Transition Matrix: Source -> Allowed Targets
    VALID_TRANSITIONS: Dict[OperationalStatusEnum, Set[OperationalStatusEnum]] = {
        OperationalStatusEnum.UNKNOWN: {
            OperationalStatusEnum.STARTING,
            OperationalStatusEnum.ACTIVE,
            OperationalStatusEnum.OFFLINE,
            OperationalStatusEnum.MAINTENANCE
        },
        OperationalStatusEnum.STARTING: {
            OperationalStatusEnum.ACTIVE,
            OperationalStatusEnum.DEGRADED,
            OperationalStatusEnum.OFFLINE
        },
        OperationalStatusEnum.ACTIVE: {
            OperationalStatusEnum.DEGRADED,
            OperationalStatusEnum.OFFLINE,
            OperationalStatusEnum.MAINTENANCE,
            OperationalStatusEnum.ISOLATED
        },
        OperationalStatusEnum.DEGRADED: {
            OperationalStatusEnum.ACTIVE,
            OperationalStatusEnum.OFFLINE,
            OperationalStatusEnum.MAINTENANCE,
            OperationalStatusEnum.ISOLATED
        },
        OperationalStatusEnum.OFFLINE: {
            OperationalStatusEnum.STARTING,
            OperationalStatusEnum.ACTIVE,
            OperationalStatusEnum.MAINTENANCE
        },
        OperationalStatusEnum.MAINTENANCE: {
            OperationalStatusEnum.STARTING,
            OperationalStatusEnum.ACTIVE,
            OperationalStatusEnum.OFFLINE
        },
        OperationalStatusEnum.ISOLATED: {
            OperationalStatusEnum.ACTIVE,
            OperationalStatusEnum.DEGRADED,
            OperationalStatusEnum.OFFLINE,
            OperationalStatusEnum.MAINTENANCE
        }
    }

    def __init__(self):
        self._current_states: Dict[str, OperationalStatusEnum] = {}
        self._history: List[OperationalTransitionRecord] = []

    def _ensure_device_registered(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found in Device Registry.")

    def getCurrentState(self, device_id: str) -> OperationalStatusEnum:
        self._ensure_device_registered(device_id)
        if device_id not in self._current_states:
            dev = device_registry.getDevice(device_id)
            # Map existing device registry state to OperationalStatusEnum
            curr_str = getattr(dev, "currentState", "ACTIVE")
            try:
                self._current_states[device_id] = OperationalStatusEnum(curr_str)
            except ValueError:
                self._current_states[device_id] = OperationalStatusEnum.ACTIVE
        return self._current_states[device_id]

    def canTransition(self, device_id: str, to_state: OperationalStatusEnum) -> bool:
        current = self.getCurrentState(device_id)
        if current == to_state:
            return True  # Idempotent transition is allowed
        allowed = self.VALID_TRANSITIONS.get(current, set())
        return to_state in allowed

    def transitionState(
        self,
        device_id: str,
        to_state: OperationalStatusEnum,
        reason: str = "Operational state change",
        trigger: str = "TELEMETRY"
    ) -> OperationalTransitionRecord:
        self._ensure_device_registered(device_id)
        current = self.getCurrentState(device_id)

        if not self.canTransition(device_id, to_state):
            raise InvalidStateTransitionError(
                f"Illegal state transition for device '{device_id}': cannot move from '{current.value}' to '{to_state.value}'."
            )

        # Update cache
        self._current_states[device_id] = to_state

        # Synchronize with DeviceRegistry and StateEngine
        dev = device_registry.getDevice(device_id)
        if dev:
            dev.currentState = to_state.value
            device_registry.updateDevice(dev)

        try:
            from services.digital_twin.core.state.state_engine import state_engine
            if device_id in state_engine._device_states:
                state_engine._device_states[device_id].operationalState = to_state
        except Exception:
            pass

        record = OperationalTransitionRecord(
            deviceId=device_id,
            fromState=current,
            toState=to_state,
            reason=reason,
            triggerSource=trigger,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self._history.append(record)
        return record

    def getStateHistory(self, device_id: Optional[str] = None) -> List[OperationalTransitionRecord]:
        if device_id:
            self._ensure_device_registered(device_id)
            return [h for h in self._history if h.deviceId == device_id]
        return list(self._history)

    def clear(self):
        self._current_states.clear()
        self._history.clear()

state_transition_engine = StateTransitionEngine()