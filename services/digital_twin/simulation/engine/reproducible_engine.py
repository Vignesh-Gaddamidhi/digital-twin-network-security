from typing import Dict, List, Optional
import random
from datetime import datetime, timezone

from packages.shared_types.src.reproducible_simulation import (
    SimulationExecutionConfig, ReproducibleSimulationEvent, SimulationRunComparisonResult
)
from packages.shared_types.src.simulation import SimulationStateEnum
from services.digital_twin.simulation.clock.simulation_clock import SimulationClock
from services.digital_twin.simulation.engine.simulation_logger import simulation_logger
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class DuplicateSimulationIdError(ValueError):
    pass

class SimulationRunNotFoundError(KeyError):
    pass

class ReproducibleEngine:
    """Coordinates deterministic network simulations with exact repeatability across execution runs."""

    def __init__(self):
        # simulationId -> SimulationExecutionConfig
        self._configs: Dict[str, SimulationExecutionConfig] = {}
        # runId -> List[ReproducibleSimulationEvent]
        self._run_events: Dict[str, List[ReproducibleSimulationEvent]] = {}
        self._active_config: Optional[SimulationExecutionConfig] = None
        self._state: SimulationStateEnum = SimulationStateEnum.STOPPED
        self._clock: SimulationClock = SimulationClock(tick_step=1.0)
        self._rng: random.Random = random.Random(12345)
        self._sequence_counter: int = 0

    @property
    def state(self) -> SimulationStateEnum:
        return self._state

    def initializeSimulation(self, config: SimulationExecutionConfig) -> SimulationExecutionConfig:
        if config.simulationId in self._configs and self._configs[config.simulationId].runId == config.runId:
            raise DuplicateSimulationIdError(f"Simulation with ID '{config.simulationId}' and run '{config.runId}' already exists.")

        self._configs[config.simulationId] = config
        self._active_config = config
        self._rng = random.Random(config.seed)
        self._clock.reset()
        self._sequence_counter = 0
        self._run_events[config.runId] = []
        self._state = SimulationStateEnum.CREATED
        return config

    def startSimulation(self) -> SimulationExecutionConfig:
        if not self._active_config:
            raise ValueError("No active simulation configured. Call initializeSimulation first.")

        self._active_config.startTime = datetime.now(timezone.utc).isoformat()
        self._clock.start()
        self._state = SimulationStateEnum.RUNNING
        return self._active_config

    def tick(self, seconds: float = 1.0, source_dev: str = "client-01", dest_dev: str = "web-01") -> Optional[ReproducibleSimulationEvent]:
        if self._state != SimulationStateEnum.RUNNING or not self._active_config:
            return None

        # Check target duration
        if self._clock.currentTime >= self._active_config.duration:
            self._state = SimulationStateEnum.COMPLETED
            self._active_config.endTime = datetime.now(timezone.utc).isoformat()
            self._clock.pause()
            return None

        self._clock.tick(seconds)
        self._sequence_counter += 1

        # Deterministic generation using isolated seeded PRNG
        src_port = self._rng.randint(49152, 65535)
        dst_port = self._rng.choice([80, 443, 53, 22, 5432])
        proto = "UDP" if dst_port == 53 else "TCP"
        payload_size = self._rng.randint(128, 2048)

        event = ReproducibleSimulationEvent(
            sequenceNumber=self._sequence_counter,
            simulationId=self._active_config.simulationId,
            runId=self._active_config.runId,
            simTimeSeconds=self._clock.currentTime,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=proto,
            sourcePort=src_port,
            destinationPort=dst_port,
            eventType="CONNECTION",
            payloadSize=payload_size,
            status="SUCCESS"
        )

        self._run_events[self._active_config.runId].append(event)
        simulation_logger.appendEvent(event)
        return event

    def runComplete(self, source_dev: str = "client-01", dest_dev: str = "web-01") -> List[ReproducibleSimulationEvent]:
        """Executes the simulation until target duration is reached."""
        self.startSimulation()
        while self._state == SimulationStateEnum.RUNNING:
            self.tick(1.0, source_dev=source_dev, dest_dev=dest_dev)
        return self.getRunEvents(self._active_config.runId)

    def getRunEvents(self, run_id: str) -> List[ReproducibleSimulationEvent]:
        if run_id not in self._run_events:
            # Fall back to reading JSONL
            return simulation_logger.readEvents(run_id=run_id)
        return list(self._run_events[run_id])

    def compareRuns(self, run1_id: str, run2_id: str) -> SimulationRunComparisonResult:
        """Performs a byte-for-byte differential audit between two simulation runs."""
        evts1 = self.getRunEvents(run1_id)
        evts2 = self.getRunEvents(run2_id)

        if len(evts1) != len(evts2):
            return SimulationRunComparisonResult(
                isIdentical=False,
                run1Id=run1_id,
                run2Id=run2_id,
                totalEventsRun1=len(evts1),
                totalEventsRun2=len(evts2),
                divergencePointSequence=min(len(evts1), len(evts2)) + 1,
                divergenceReason=f"Event count mismatch: Run 1 has {len(evts1)}, Run 2 has {len(evts2)}"
            )

        for i, (e1, e2) in enumerate(zip(evts1, evts2)):
            seq = i + 1
            if e1.sequenceNumber != e2.sequenceNumber:
                return SimulationRunComparisonResult(
                    isIdentical=False, run1Id=run1_id, run2Id=run2_id, totalEventsRun1=len(evts1), totalEventsRun2=len(evts2),
                    divergencePointSequence=seq, divergenceReason=f"Sequence number mismatch: {e1.sequenceNumber} vs {e2.sequenceNumber}"
                )
            if e1.simTimeSeconds != e2.simTimeSeconds:
                return SimulationRunComparisonResult(
                    isIdentical=False, run1Id=run1_id, run2Id=run2_id, totalEventsRun1=len(evts1), totalEventsRun2=len(evts2),
                    divergencePointSequence=seq, divergenceReason=f"Simulated time mismatch: {e1.simTimeSeconds} vs {e2.simTimeSeconds}"
                )
            if (e1.sourceDevice != e2.sourceDevice or e1.destinationDevice != e2.destinationDevice or
                e1.protocol != e2.protocol or e1.sourcePort != e2.sourcePort or
                e1.destinationPort != e2.destinationPort or e1.payloadSize != e2.payloadSize):
                return SimulationRunComparisonResult(
                    isIdentical=False, run1Id=run1_id, run2Id=run2_id, totalEventsRun1=len(evts1), totalEventsRun2=len(evts2),
                    divergencePointSequence=seq, divergenceReason=f"Event attributes diverged at sequence {seq} (Ports: {e1.sourcePort}->{e1.destinationPort} vs {e2.sourcePort}->{e2.destinationPort})"
                )

        return SimulationRunComparisonResult(
            isIdentical=True,
            run1Id=run1_id,
            run2Id=run2_id,
            totalEventsRun1=len(evts1),
            totalEventsRun2=len(evts2),
            divergencePointSequence=None,
            divergenceReason=None
        )

    def clear(self):
        self._configs.clear()
        self._run_events.clear()
        self._active_config = None
        self._state = SimulationStateEnum.STOPPED
        self._clock.reset()
        self._sequence_counter = 0
        simulation_logger.clear()

reproducible_engine = ReproducibleEngine()