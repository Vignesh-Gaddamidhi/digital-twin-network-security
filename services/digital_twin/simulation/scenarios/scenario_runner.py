import json
import random
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import uuid

from packages.shared_types.src.master_scenario import (
    MasterScenarioDefinition, MasterScenarioStageConfig,
    ScenarioStageTypeEnum, ScenarioExecutionStatus
)
from packages.shared_types.src.normal_traffic import NormalTrafficScenarioConfig
from packages.shared_types.src.traffic_spike import TrafficSpikeProfile
from packages.shared_types.src.connection_anomaly import ConnectionAnomalyProfile, ConnectionAnomalyPatternEnum
from packages.shared_types.src.port_anomaly import PortAnomalyProfile
from packages.shared_types.src.repeated_connection import RepeatedConnectionProfile
from packages.shared_types.src.protocol_traffic import UnifiedTrafficEventModel

from services.digital_twin.simulation.generators.normal_traffic_orchestrator import normal_orchestrator
from services.digital_twin.simulation.generators.traffic_spike_engine import traffic_spike_engine
from services.digital_twin.simulation.generators.connection_anomaly_engine import connection_anomaly_engine
from services.digital_twin.simulation.generators.port_anomaly_engine import port_anomaly_engine
from services.digital_twin.simulation.generators.protocol_anomaly_engine import protocol_anomaly_engine
from services.digital_twin.simulation.generators.repeated_connection_engine import repeated_connection_engine

class ScenarioRunner:
    """Master Scenario Runner executing sequential normal and abnormal traffic workflows."""

    def __init__(self, export_dir: Optional[Path] = None):
        self._scenario: Optional[MasterScenarioDefinition] = None
        self._status: Optional[ScenarioExecutionStatus] = None
        self._rng: Optional[random.Random] = None
        self._is_paused: bool = False
        self._collected_events: List[Dict[str, Any]] = []

        if export_dir:
            self.export_dir = export_dir
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
            self.export_dir = base_dir / "data" / "simulation" / "runs"
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def loadScenario(self, scenario: MasterScenarioDefinition) -> MasterScenarioDefinition:
        self.validateScenario(scenario)
        self._scenario = scenario
        self.reset()
        return scenario

    def validateScenario(self, scenario: MasterScenarioDefinition):
        if not scenario.stages:
            raise ValueError("Scenario must contain at least one execution stage.")
        for idx, stage in enumerate(scenario.stages):
            if stage.durationSeconds <= 0:
                raise ValueError(f"Stage {idx} duration must be positive. Got {stage.durationSeconds}")

    def initialize(self) -> ScenarioExecutionStatus:
        if not self._scenario:
            raise ValueError("No scenario loaded. Call loadScenario first.")

        run_id = f"run-p7-{uuid.uuid4().hex[:8]}"
        self._rng = random.Random(self._scenario.seed)
        self._is_paused = False
        self._collected_events.clear()

        self._status = ScenarioExecutionStatus(
            scenarioId=self._scenario.scenarioId,
            runId=run_id,
            state="CREATED",
            currentStageIndex=0,
            totalStages=len(self._scenario.stages),
            virtualTimeSeconds=0.0,
            totalPacketsEmitted=0,
            totalEventsLogged=0,
            anomaliesTriggeredCount=0,
            startedAt=datetime.now(timezone.utc).isoformat()
        )
        return self._status

    def run(self) -> ScenarioExecutionStatus:
        if not self._status:
            self.initialize()

        self._status.state = "RUNNING"
        self._status.lastTickAt = datetime.now(timezone.utc).isoformat()

        # Execute each stage sequentially
        for idx, stage in enumerate(self._scenario.stages):
            self._status.currentStageIndex = idx + 1
            self._execute_stage(stage)
            self._status.virtualTimeSeconds += stage.durationSeconds

        self._status.state = "COMPLETED"
        return self._status

    def _execute_stage(self, stage: MasterScenarioStageConfig):
        st = stage.stageType
        sim_id = self._status.runId

        # 1. NORMAL_BASELINE & RECOVERY
        if st in (ScenarioStageTypeEnum.NORMAL_BASELINE, ScenarioStageTypeEnum.RECOVERY):
            cfg = NormalTrafficScenarioConfig(
                scenarioId=f"{sim_id}-{stage.stageId}",
                name=f"Normal-{stage.stageId}",
                durationSeconds=stage.durationSeconds,
                seed=self._rng.randint(1000, 99999),
                clientDevices=[stage.affectedDevice],
                webServers=[stage.targetDevice] if "web" in stage.targetDevice else ["web-01"],
                dnsServers=["dns-01"],
                genericServers=["server-01", "db-01"]
            )
            baseline = normal_orchestrator.runScenario(cfg, sync_to_twin=True)
            self._status.totalPacketsEmitted += baseline.totalPacketsTransferred
            self._status.totalEventsLogged += baseline.totalEventsCount

        # 2. TRAFFIC_SPIKE
        elif st == ScenarioStageTypeEnum.TRAFFIC_SPIKE:
            prof = TrafficSpikeProfile(
                affectedDevice=stage.affectedDevice,
                targetDevice=stage.targetDevice,
                targetPort=stage.targetPort,
                baselineRate=100.0,
                spikeRate=800.0 * stage.intensity,
                spikeDuration=max(1, stage.durationSeconds - 4),
                rampUpTime=2,
                rampDownTime=2
            )
            res = traffic_spike_engine.runSpikeScenario(prof, sync_to_twin=True, simulation_id=sim_id)
            self._status.totalPacketsEmitted += res.totalEventsEmitted
            self._status.totalEventsLogged += len(res.telemetryTimeline)
            self._status.anomaliesTriggeredCount += 1

        # 3. CONNECTION_ANOMALY
        elif st == ScenarioStageTypeEnum.CONNECTION_ANOMALY:
            prof = ConnectionAnomalyProfile(
                affectedDevice=stage.affectedDevice,
                targetDevice=stage.targetDevice,
                targetPort=stage.targetPort,
                normalConnectionRate=5,
                abnormalConnectionRate=int(100 * stage.intensity),
                durationSeconds=stage.durationSeconds,
                lifecyclePattern=ConnectionAnomalyPatternEnum.HIGH_NEW_HIGH_FAILED
            )
            res = connection_anomaly_engine.runAnomalyScenario(prof, sync_to_twin=True, simulation_id=sim_id)
            self._status.totalPacketsEmitted += res.totalTransactions
            self._status.totalEventsLogged += 1
            self._status.anomaliesTriggeredCount += 1

        # 4. PORT_ANOMALY
        elif st == ScenarioStageTypeEnum.PORT_ANOMALY:
            prof = PortAnomalyProfile(
                affectedDevice=stage.affectedDevice,
                targetDevice=stage.targetDevice,
                probedPorts=[21, 22, 25, 53, 80, 110, 443, 8080, 8443]
            )
            res = port_anomaly_engine.runPortAnomalyScenario(prof, simulation_id=sim_id)
            self._status.totalPacketsEmitted += res.totalAttempts
            self._status.totalEventsLogged += 1
            self._status.anomaliesTriggeredCount += 1

        # 5. PROTOCOL_ANOMALY
        elif st == ScenarioStageTypeEnum.PROTOCOL_ANOMALY:
            res = protocol_anomaly_engine.runThreeStageScenario(
                source_dev=stage.affectedDevice,
                dest_dev=stage.targetDevice,
                window_duration=max(1, int(stage.durationSeconds / 3)),
                simulation_id=sim_id
            )
            self._status.totalPacketsEmitted += res.totalEvents
            self._status.totalEventsLogged += len(res.detectedAnomalies)
            self._status.anomaliesTriggeredCount += 1

        # 6. REPEATED_CONNECTION
        elif st == ScenarioStageTypeEnum.REPEATED_CONNECTION:
            prof = RepeatedConnectionProfile(
                sourceDevice=stage.affectedDevice,
                destinationDevice=stage.targetDevice,
                destinationPort=stage.targetPort,
                attemptCount=int(100 * stage.intensity),
                windowSeconds=stage.durationSeconds
            )
            ev, pkts = repeated_connection_engine.runScenario(prof, simulation_id=sim_id)
            self._status.totalPacketsEmitted += len(pkts)
            self._status.totalEventsLogged += 1
            self._status.anomaliesTriggeredCount += 1

    def pause(self) -> ScenarioExecutionStatus:
        if self._status:
            self._status.state = "PAUSED"
            self._is_paused = True
        return self._status

    def resume(self) -> ScenarioExecutionStatus:
        if self._status:
            self._status.state = "RUNNING"
            self._is_paused = False
        return self._status

    def stop(self) -> ScenarioExecutionStatus:
        if self._status:
            self._status.state = "STOPPED"
        return self._status

    def reset(self):
        self._status = None
        self._is_paused = False
        self._collected_events.clear()

    def replay(self) -> ScenarioExecutionStatus:
        if not self._scenario:
            raise ValueError("No scenario loaded to replay.")
        self.reset()
        self.initialize()
        return self.run()

    def exportResults(self) -> Path:
        if not self._status:
            raise ValueError("No run status to export.")
        out_file = self.export_dir / f"{self._status.runId}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(self._status.model_dump(), f, indent=2)
        return out_file

    def getStatus(self) -> Optional[ScenarioExecutionStatus]:
        return self._status

scenario_runner = ScenarioRunner()