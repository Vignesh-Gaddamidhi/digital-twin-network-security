from typing import Dict, List, Optional
from packages.shared_types.src.attack_scenario import AttackScenarioModel

class ScenarioAlreadyExistsError(ValueError):
    pass

class ScenarioNotFoundError(KeyError):
    pass

class AttackScenarioRegistry:
    """Central registry of configured Attack Scenarios."""

    def __init__(self):
        self._scenarios: Dict[str, AttackScenarioModel] = {}

    def register(self, scenario: AttackScenarioModel) -> AttackScenarioModel:
        if scenario.scenarioId in self._scenarios:
            raise ScenarioAlreadyExistsError(f"Scenario '{scenario.scenarioId}' is already registered.")
        self._scenarios[scenario.scenarioId] = scenario
        return scenario

    def get(self, scenario_id: str) -> Optional[AttackScenarioModel]:
        return self._scenarios.get(scenario_id)

    def listScenarios(self) -> List[AttackScenarioModel]:
        return list(self._scenarios.values())

    def clear(self):
        self._scenarios.clear()

attack_scenario_registry = AttackScenarioRegistry()