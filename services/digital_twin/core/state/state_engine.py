from typing import Dict, List, Optional
from datetime import datetime, timezone
from packages.shared_types.src.state import CurrentState, StateTransitionRecord
from services.twin_engine.src.core.twin_state import DeviceEntity

class StateEngine:
    """Manages operational telemetry metrics and validates FSM transitions."""

    def __init__(self):
        self._history: List[StateTransitionRecord] = []

    def update_operational_state(self, device: DeviceEntity, cpu_pct: float, mem_pct: float, pps: float, bps: float, status: str = "ONLINE") -> CurrentState:
        device.current_state.cpu_usage_pct = cpu_pct
        device.current_state.memory_usage_pct = mem_pct
        device.current_state.network_state.packet_rate_pps = pps
        device.current_state.network_state.byte_rate_bps = bps
        device.current_state.status = status
        device.status = status
        device.current_state.last_updated = datetime.now(timezone.utc).isoformat()
        return device.current_state

    def update_security_state(self, device: DeviceEntity, new_state: str, trigger_source: str, reason: str) -> Optional[StateTransitionRecord]:
        prev_state = device.security_state_model.security_status
        if prev_state == new_state:
            return None

        record = StateTransitionRecord(
            device_id=device.id,
            previous_state=prev_state,
            new_state=new_state,
            trigger_source=trigger_source,
            reason=reason,
            risk_score=device.security_state_model.risk_score
        )
        self._history.append(record)

        device.security_state_model.security_status = new_state
        device.security_state_model.last_security_event = trigger_source
        device.security_state_model.last_evaluated = datetime.now(timezone.utc).isoformat()
        device.security_state = "COMPROMISED" if new_state == "COMPROMISED" else "SUSPICIOUS" if new_state in ("SUSPICIOUS", "AT_RISK") else "HEALTHY"
        return record

    def get_history(self, device_id: Optional[str] = None) -> List[StateTransitionRecord]:
        if device_id:
            return [h for h in self._history if h.device_id == device_id]
        return list(self._history)