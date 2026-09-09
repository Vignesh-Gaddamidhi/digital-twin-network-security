from typing import Set, Dict
from packages.shared_types.src.attack_scenario import AttackScenarioStateEnum

class InvalidStateTransitionError(ValueError):
    pass

class AttackScenarioStateMachine:
    """Manages valid lifecycle transitions for Attack Scenarios."""

    VALID_TRANSITIONS: Dict[AttackScenarioStateEnum, Set[AttackScenarioStateEnum]] = {
        AttackScenarioStateEnum.CREATED: {
            AttackScenarioStateEnum.VALIDATING,
            AttackScenarioStateEnum.CANCELLED,
            AttackScenarioStateEnum.FAILED
        },
        AttackScenarioStateEnum.VALIDATING: {
            AttackScenarioStateEnum.READY,
            AttackScenarioStateEnum.FAILED,
            AttackScenarioStateEnum.CANCELLED
        },
        AttackScenarioStateEnum.READY: {
            AttackScenarioStateEnum.RUNNING,
            AttackScenarioStateEnum.CANCELLED
        },
        AttackScenarioStateEnum.RUNNING: {
            AttackScenarioStateEnum.DETECTED,
            AttackScenarioStateEnum.RECOVERING,
            AttackScenarioStateEnum.COMPLETED,
            AttackScenarioStateEnum.FAILED,
            AttackScenarioStateEnum.CANCELLED
        },
        AttackScenarioStateEnum.DETECTED: {
            AttackScenarioStateEnum.RECOVERING,
            AttackScenarioStateEnum.COMPLETED,
            AttackScenarioStateEnum.FAILED
        },
        AttackScenarioStateEnum.RECOVERING: {
            AttackScenarioStateEnum.COMPLETED,
            AttackScenarioStateEnum.FAILED
        },
        AttackScenarioStateEnum.COMPLETED: set(),
        AttackScenarioStateEnum.FAILED: {
            AttackScenarioStateEnum.VALIDATING,
            AttackScenarioStateEnum.CREATED
        },
        AttackScenarioStateEnum.CANCELLED: set()
    }

    def __init__(self, initial_state: AttackScenarioStateEnum = AttackScenarioStateEnum.CREATED):
        self._current_state = initial_state

    @property
    def current_state(self) -> AttackScenarioStateEnum:
        return self._current_state

    def transition_to(self, new_state: AttackScenarioStateEnum) -> AttackScenarioStateEnum:
        allowed = self.VALID_TRANSITIONS.get(self._current_state, set())
        if new_state not in allowed:
            raise InvalidStateTransitionError(
                f"Cannot transition scenario from '{self._current_state.value}' to '{new_state.value}'. "
                f"Valid targets: {[s.value for s in allowed]}"
            )
        self._current_state = new_state
        return self._current_state