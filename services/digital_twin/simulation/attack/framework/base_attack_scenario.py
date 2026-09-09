from abc import ABC, abstractmethod
from typing import List, Dict, Any
from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioExecutionStatus, AttackScenarioStateEnum
)
from packages.shared_types.src.protocol_traffic import UnifiedTrafficEventModel
from services.digital_twin.simulation.attack.framework.scenario_state_machine import AttackScenarioStateMachine
from services.digital_twin.simulation.attack.framework.scenario_validator import (
    ScenarioValidator, ScenarioPreconditionFailedError
)

class BaseAttackScenario(ABC):
    """Abstract base implementation for all attack scenarios in Phase 8."""

    def __init__(self, definition: AttackScenarioModel):
        self.definition = definition
        self.state_machine = AttackScenarioStateMachine(AttackScenarioStateEnum.CREATED)
        self.status = AttackScenarioExecutionStatus(
            scenarioId=definition.scenarioId,
            currentState=AttackScenarioStateEnum.CREATED
        )

    def validate(self) -> bool:
        self.state_machine.transition_to(AttackScenarioStateEnum.VALIDATING)
        self.status.currentState = AttackScenarioStateEnum.VALIDATING

        valid, errors = ScenarioValidator.validate_preconditions(self.definition)
        if not valid:
            self.state_machine.transition_to(AttackScenarioStateEnum.FAILED)
            self.status.currentState = AttackScenarioStateEnum.FAILED
            self.status.errorReason = "; ".join(errors)
            raise ScenarioPreconditionFailedError(self.status.errorReason)

        self.state_machine.transition_to(AttackScenarioStateEnum.READY)
        self.status.currentState = AttackScenarioStateEnum.READY
        return True

    def run(self) -> AttackScenarioExecutionStatus:
        if self.state_machine.current_state != AttackScenarioStateEnum.READY:
            self.validate()

        self.state_machine.transition_to(AttackScenarioStateEnum.RUNNING)
        self.status.currentState = AttackScenarioStateEnum.RUNNING

        try:
            # 1. Generate Synthetic Pattern
            events = self.generate_traffic_events()
            
            # 2. Check Expected Indicators
            observed = self.evaluate_indicators(events)
            self.status.indicatorsObserved = observed
            if observed:
                self.state_machine.transition_to(AttackScenarioStateEnum.DETECTED)
                self.status.currentState = AttackScenarioStateEnum.DETECTED

            # 3. Apply Recovery
            if self.definition.recovery.autoRecover:
                self.state_machine.transition_to(AttackScenarioStateEnum.RECOVERING)
                self.status.currentState = AttackScenarioStateEnum.RECOVERING
                self.recover()

            self.state_machine.transition_to(AttackScenarioStateEnum.COMPLETED)
            self.status.currentState = AttackScenarioStateEnum.COMPLETED

        except Exception as e:
            self.state_machine.transition_to(AttackScenarioStateEnum.FAILED)
            self.status.currentState = AttackScenarioStateEnum.FAILED
            self.status.errorReason = str(e)
            raise

        return self.status

    @abstractmethod
    def generate_traffic_events(self) -> List[UnifiedTrafficEventModel]:
        """Generates the synthetic protocol frames corresponding to this scenario."""
        pass

    @abstractmethod
    def evaluate_indicators(self, events: List[UnifiedTrafficEventModel]) -> List[str]:
        """Verifies if expected security indicators were manifested in the generated events."""
        pass

    @abstractmethod
    def recover(self):
        """Restores the digital twin back to baseline conditions."""
        pass