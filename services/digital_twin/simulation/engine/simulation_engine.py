from typing import Dict, List, Optional
import random
from datetime import datetime, timezone

from packages.shared_types.src.simulation import (
    ScenarioModel, SimulationStateEnum, SimulationEventModel,
    SimulationEventTypeEnum, SimulationStatusSnapshotModel
)
from services.digital_twin.simulation.clock.simulation_clock import SimulationClock
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class InvalidSimulationStateTransitionError(ValueError):
    pass

class ScenarioNotFoundError(KeyError):
    pass

class SimulationEngine:
    """Coordinates scenario execution, virtual clock advancement, and synthetic event emission."""

    # Valid FSM transitions
    VALID_TRANSITIONS = {
        SimulationStateEnum.CREATED: {SimulationStateEnum.RUNNING, SimulationStateEnum.STOPPED, SimulationStateEnum.FAILED},
        SimulationStateEnum.RUNNING: {SimulationStateEnum.PAUSED, SimulationStateEnum.COMPLETED, SimulationStateEnum.STOPPED, SimulationStateEnum.FAILED},
        SimulationStateEnum.PAUSED: {SimulationStateEnum.RUNNING, SimulationStateEnum.STOPPED, SimulationStateEnum.FAILED},
        SimulationStateEnum.COMPLETED: {SimulationStateEnum.CREATED},
        SimulationStateEnum.STOPPED: {SimulationStateEnum.CREATED},
        SimulationStateEnum.FAILED: {SimulationStateEnum.CREATED}
    }

    def __init__(self):
        self._scenario: Optional[ScenarioModel] = None
        self._state: SimulationStateEnum = SimulationStateEnum.STOPPED
        self._clock: SimulationClock = SimulationClock(tick_step=1.0)
        self._rng: random.Random = random.Random(12345)
        self._events: List[SimulationEventModel] = []
        self._start_wall_time: Optional[str] = None

    @property
    def state(self) -> SimulationStateEnum:
        return self._state

    def _transition_state(self, new_state: SimulationStateEnum):
        allowed = self.VALID_TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            raise InvalidSimulationStateTransitionError(
                f"Cannot transition simulation from '{self._state.value}' to '{new_state.value}'."
            )
        self._state = new_state

    def createSimulation(self, scenario: ScenarioModel) -> ScenarioModel:
        # Validate that devices exist in registry if provided
        for dev_id in scenario.devices:
            if not device_registry.getDevice(dev_id):
                raise DeviceNotFoundError(f"Device '{dev_id}' referenced in scenario does not exist in Device Registry.")

        self.resetSimulation()
        self._scenario = scenario
        self._rng = random.Random(scenario.seed)
        self._state = SimulationStateEnum.CREATED
        return scenario

    def startSimulation(self) -> SimulationStatusSnapshotModel:
        if not self._scenario:
            raise ScenarioNotFoundError("No simulation scenario configured. Call createSimulation first.")

        if self._state == SimulationStateEnum.PAUSED:
            return self.resumeSimulation()

        self._transition_state(SimulationStateEnum.RUNNING)
        self._start_wall_time = datetime.now(timezone.utc).isoformat()
        self._clock.start()
        return self.getSimulationState()

    def pauseSimulation(self) -> SimulationStatusSnapshotModel:
        self._transition_state(SimulationStateEnum.PAUSED)
        self._clock.pause()
        return self.getSimulationState()

    def resumeSimulation(self) -> SimulationStatusSnapshotModel:
        self._transition_state(SimulationStateEnum.RUNNING)
        self._clock.resume()
        return self.getSimulationState()

    def stopSimulation(self) -> SimulationStatusSnapshotModel:
        self._transition_state(SimulationStateEnum.STOPPED)
        self._clock.pause()
        return self.getSimulationState()

    def resetSimulation(self):
        self._state = SimulationStateEnum.STOPPED
        self._clock.reset()
        self._events.clear()
        self._scenario = None
        self._start_wall_time = None

    def tick(self, seconds: float = 1.0) -> Optional[SimulationEventModel]:
        """Advances simulation by specified seconds. Generates an event if running."""
        if self._state != SimulationStateEnum.RUNNING:
            return None

        new_time = self._clock.tick(seconds)

        # Check for scenario completion
        if self._scenario and new_time >= self._scenario.duration:
            self._transition_state(SimulationStateEnum.COMPLETED)
            self._clock.pause()

        # Emit synthetic traffic event
        return self.generateEvent()

    def generateEvent(
        self,
        source_dev: Optional[str] = None,
        dest_dev: Optional[str] = None,
        event_type: SimulationEventTypeEnum = SimulationEventTypeEnum.CONNECTION
    ) -> Optional[SimulationEventModel]:
        if not self._scenario or self._state != SimulationStateEnum.RUNNING:
            return None

        # Pick devices from scenario or default pool
        dev_list = self._scenario.devices if self._scenario.devices else ["client-01", "web-01"]
        src = source_dev or (dev_list[0] if len(dev_list) > 0 else "client-01")
        dst = dest_dev or (dev_list[1] if len(dev_list) > 1 else "web-01")

        src_port = self._rng.randint(49152, 65535)
        dst_port = 443 if not self._scenario.trafficProfiles else self._scenario.trafficProfiles[0].destinationPort
        proto = "TCP" if not self._scenario.trafficProfiles else self._scenario.trafficProfiles[0].protocol
        payload_size = self._rng.randint(256, 4096)

        event = SimulationEventModel(
            scenarioId=self._scenario.scenarioId,
            simTimeSeconds=self._clock.currentTime,
            sourceDevice=src,
            destinationDevice=dst,
            protocol=proto,
            sourcePort=src_port,
            destinationPort=dst_port,
            eventType=event_type,
            payloadSize=payload_size,
            status="SUCCESS"
        )
        self._events.append(event)
        return event

    def getSimulationState(self) -> SimulationStatusSnapshotModel:
        return SimulationStatusSnapshotModel(
            scenarioId=self._scenario.scenarioId if self._scenario else None,
            state=self._state,
            simCurrentTimeSeconds=self._clock.currentTime,
            targetDuration=self._scenario.duration if self._scenario else 0,
            eventsGeneratedCount=len(self._events),
            isClockRunning=self._clock.isRunning,
            startedAt=self._start_wall_time,
            lastTickAt=self._clock._last_tick_wall_time
        )

    def getSimulationEvents(self, limit: Optional[int] = None) -> List[SimulationEventModel]:
        if limit:
            return self._events[-limit:]
        return list(self._events)

simulation_engine = SimulationEngine()