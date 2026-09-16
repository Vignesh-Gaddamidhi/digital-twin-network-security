from typing import Tuple
from security.response.models.action import ResponseActionType

class StateTransitionEngine:
    """Manages legal security-state transitions for simulated response actions."""

    VALID_TRANSITIONS = {
        "NORMAL": ["MONITORED", "AT_RISK", "ISOLATED", "QUARANTINED"],
        "MONITORED": ["SUSPICIOUS", "AT_RISK", "ISOLATED", "NORMAL"],
        "SUSPICIOUS": ["AT_RISK", "ISOLATED", "QUARANTINED", "MONITORED"],
        "AT_RISK": ["COMPROMISED", "ISOLATED", "QUARANTINED", "NORMAL"],
        "COMPROMISED": ["ISOLATED", "QUARANTINED", "NORMAL"],
        "ISOLATED": ["NORMAL", "MONITORED"],
        "QUARANTINED": ["NORMAL", "MONITORED"]
    }

    @classmethod
    def resolve_target_state(cls, action: ResponseActionType, current_state: str) -> Tuple[bool, str, str]:
        current_upper = current_state.upper()

        if action == ResponseActionType.ISOLATE_DEVICE:
            target_state = "ISOLATED"
        elif action == ResponseActionType.QUARANTINE_ENDPOINT:
            target_state = "QUARANTINED"
        elif action == ResponseActionType.INCREASE_SECURITY_LEVEL:
            target_state = "MONITORED"
        elif action == ResponseActionType.MARK_DEVICE_AT_RISK:
            target_state = "AT_RISK"
        elif action in (ResponseActionType.BLOCK_CONNECTION, ResponseActionType.DISABLE_SERVICE):
            target_state = current_upper  # Device state remains unchanged; edge/port is altered
        else:
            return False, current_upper, f"Unknown action: {action}"

        # Legality check
        if target_state != current_upper and current_upper in cls.VALID_TRANSITIONS:
            if target_state not in cls.VALID_TRANSITIONS[current_upper]:
                return False, current_upper, f"Illegal transition from {current_upper} to {target_state}"

        return True, target_state, f"Transition from {current_upper} to {target_state} authorized."

state_transition_engine = StateTransitionEngine()