import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioStateEnum, AttackScenarioExecutionStatus
)
from packages.shared_types.src.traffic_pattern import (
    GenericTrafficPatternModel, PatternTypeEnum, ConnectionBehaviourEnum, PatternTimingConfig
)
from packages.shared_types.src.attack_indicators import ExpectedIndicatorModel
from packages.shared_types.src.attack_recovery import (
    ScenarioRecoveryPlan, RecoveryStrategyEnum, RecoveryExecutionReport
)
from packages.shared_types.src.scenario_result import ScenarioResult
from packages.shared_types.src.protocol_traffic import UnifiedTrafficEventModel

from services.digital_twin.simulation.attack.framework.scenario_state_machine import AttackScenarioStateMachine
from services.digital_twin.simulation.attack.validation.precondition_engine import precondition_engine
from services.digital_twin.simulation.attack.generators.pattern_generator_engine import pattern_generator_engine
from services.digital_twin.simulation.attack.indicators.indicator_matcher import indicator_matcher
from services.digital_twin.simulation.attack.framework.severity_engine import severity_engine
from services.digital_twin.simulation.attack.recovery.recovery_engine import recovery_engine

from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine

class AttackScenarioRunner:
    """Master generic attack scenario execution runner coordinating all Phase 8 frameworks."""

    def __init__(self, export_dir: Optional[Path] = None):
        self.scenario: Optional[AttackScenarioModel] = None
        self.state_machine: Optional[AttackScenarioStateMachine] = None
        self.status: Optional[AttackScenarioExecutionStatus] = None
        self.result: Optional[ScenarioResult] = None
        self._emitted_events: List[UnifiedTrafficEventModel] = []
        self._is_paused: bool = False

        if export_dir:
            self.export_dir = export_dir
        else:
            base_dir = Path(__file__).resolve().parents[5]
            self.export_dir = base_dir / "data" / "simulation" / "attack_runs"
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def loadScenario(self, scenario: AttackScenarioModel) -> AttackScenarioModel:
        self.scenario = scenario
        self.state_machine = AttackScenarioStateMachine(AttackScenarioStateEnum.CREATED)
        self.status = AttackScenarioExecutionStatus(
            scenarioId=scenario.scenarioId,
            currentState=AttackScenarioStateEnum.CREATED
        )
        self.result = ScenarioResult(
            scenarioId=scenario.scenarioId,
            runId=self.status.runId,
            affectedDevices=[scenario.targetDevice],
            finalState="CREATED"
        )
        self._emitted_events.clear()
        self._is_paused = False
        return self.scenario

    def validateScenario(self) -> bool:
        if not self.scenario or not self.state_machine:
            raise ValueError("No scenario loaded to validate.")

        self.state_machine.transition_to(AttackScenarioStateEnum.VALIDATING)
        self.status.currentState = AttackScenarioStateEnum.VALIDATING

        # Check preconditions
        rules = getattr(self.scenario, "preconditionRules", [])
        report = precondition_engine.validate_scenario_preconditions(
            scenario_id=self.scenario.scenarioId,
            target_device=self.scenario.targetDevice,
            rules=rules,
            source_device=self.scenario.sourceDevice
        )

        if not report.isValid:
            self.state_machine.transition_to(AttackScenarioStateEnum.FAILED)
            self.status.currentState = AttackScenarioStateEnum.FAILED
            self.status.errorReason = "; ".join(report.failureReasons)
            self.result.finalState = "FAILED"
            self.result.details["precondition_failures"] = report.failureReasons
            return False

        self.state_machine.transition_to(AttackScenarioStateEnum.READY)
        self.status.currentState = AttackScenarioStateEnum.READY
        self.result.finalState = "READY"
        return True

    def initializeScenario(self) -> AttackScenarioExecutionStatus:
        if not self.scenario:
            raise ValueError("No scenario loaded.")
        if self.state_machine.current_state != AttackScenarioStateEnum.READY:
            self.validateScenario()
        return self.status

    def startScenario(self) -> AttackScenarioExecutionStatus:
        if not self.state_machine:
            raise ValueError("Runner uninitialized.")
        self.state_machine.transition_to(AttackScenarioStateEnum.RUNNING)
        self.status.currentState = AttackScenarioStateEnum.RUNNING
        self.result.finalState = "RUNNING"
        self.result.startTime = datetime.now(timezone.utc).isoformat()
        return self.status

    def pauseScenario(self) -> AttackScenarioExecutionStatus:
        if self.status and self.status.currentState == AttackScenarioStateEnum.RUNNING:
            self._is_paused = True
        return self.status

    def resumeScenario(self) -> AttackScenarioExecutionStatus:
        if self.status and self._is_paused:
            self._is_paused = False
        return self.status

    def stopScenario(self) -> AttackScenarioExecutionStatus:
        if self.state_machine:
            self.state_machine.transition_to(AttackScenarioStateEnum.CANCELLED)
            self.status.currentState = AttackScenarioStateEnum.CANCELLED
            self.result.finalState = "CANCELLED"
        return self.status

    def detectIndicators(self) -> List[str]:
        if not self.scenario or not self._emitted_events:
            return []

        # Convert ExpectedIndicator list
        exp_list: List[ExpectedIndicatorModel] = []
        for ind in self.scenario.expectedIndicators:
            try:
                exp_list.append(ExpectedIndicatorModel(
                    indicatorId=ind.indicatorId,
                    type=ind.indicatorType,
                    description=ind.description,
                    metric=ind.thresholdMetric,
                    threshold=ind.expectedThreshold
                ))
            except Exception:
                pass

        rep = indicator_matcher.verify_scenario_indicators(
            scenario_id=self.scenario.scenarioId,
            expected_indicators=exp_list,
            events=self._emitted_events,
            duration_seconds=float(self.scenario.durationSeconds)
        )

        observed = [m.type.value for m in rep.matchedIndicators]
        self.status.indicatorsObserved = observed
        self.result.indicatorsObserved = observed
        if observed:
            self.state_machine.transition_to(AttackScenarioStateEnum.DETECTED)
            self.status.currentState = AttackScenarioStateEnum.DETECTED
            self.status.detectedAt = datetime.now(timezone.utc).isoformat()
            self.result.alertsGenerated = [f"ALERT-{o}" for o in observed]
        return observed

    def recoverScenario(self) -> RecoveryExecutionReport:
        if not self.scenario or not self.state_machine:
            raise ValueError("No scenario running to recover.")

        self.state_machine.transition_to(AttackScenarioStateEnum.RECOVERING)
        self.status.currentState = AttackScenarioStateEnum.RECOVERING

        rec_plan = ScenarioRecoveryPlan(
            scenarioId=self.scenario.scenarioId,
            strategy=RecoveryStrategyEnum.RESTORE_BASELINE,
            affectedDevices=[self.scenario.targetDevice],
            restoreTraffic=getattr(self.scenario.recovery, 'restoreTraffic', getattr(self.scenario.recovery, 'restoreNormalTraffic', True)),
            restoreConnections=self.scenario.recovery.resetSocketConnections,
            revertPortMutations=self.scenario.recovery.revertPortMutations,
            verificationRequired=True
        )

        rep = recovery_engine.execute_recovery(rec_plan)
        self.result.recoveryStatus = "VERIFIED_RESTORED" if rep.verified else "RECOVERED_UNVERIFIED"
        self.result.recoveryVerified = rep.verified
        self.status.recoveredAt = rep.recoveredAt
        return rep

    def verifyRecovery(self) -> bool:
        if not self.result:
            return False
        return bool(self.result.recoveryVerified)

    def executeScenario(self) -> ScenarioResult:
        """Executes full canonical 12-step pipeline from start to healed finish."""
        if not self.scenario:
            raise ValueError("No scenario loaded to execute.")

        # 1. Validate & Check Preconditions
        is_valid = self.validateScenario()
        if not is_valid:
            return self.result

        # 2. Risk Assessment
        risk_rep = severity_engine.assess_risk(self.scenario)
        self.result.riskScore = risk_rep.riskScore
        self.result.riskLevel = risk_rep.riskLevel.value

        # 3. Start Execution
        self.startScenario()

        # 4. Generate Synthetic Traffic Events from Pattern
        tp = self.scenario.trafficPattern
        ports = tp.parameters.get("ports", [80, 443])

        pat_model = GenericTrafficPatternModel(
            patternType=PatternTypeEnum(tp.patternType.upper()),
            protocol=tp.protocol.upper(),
            sourceDevice=self.scenario.sourceDevice,
            targetDevice=self.scenario.targetDevice,
            destinationPorts=ports,
            timing=PatternTimingConfig(
                durationSeconds=float(self.scenario.durationSeconds),
                rateEventsPerSecond=float(len(ports)) / max(1.0, float(self.scenario.durationSeconds))
            ),
            seed=12345
        )

        _, events = pattern_generator_engine.generate_events(pat_model, simulation_id=self.status.runId)
        self._emitted_events = events
        self.result.eventsGenerated = len(events)
        self.result.bytesGenerated = sum(e.bytes for e in events)

        # 5. Twin State Strains (simulate physical host strain)
        performance_state_engine.updateCpu(self.scenario.targetDevice, 85.0, source="ATTACK_SIM")
        network_state_engine.updateNetworkMetrics(
            device_id=self.scenario.targetDevice,
            network_utilisation=90.0,
            bytes_sent=0,
            bytes_received=self.result.bytesGenerated,
            packets_sent=0,
            packets_received=self.result.eventsGenerated
        )
        self.result.stateChanges = {
            "cpu": "25% -> 85%",
            "utilisation": "20% -> 90%",
            "active_sockets": f"+{len(events)}"
        }

        # 6. Detect Expected Indicators
        self.detectIndicators()

        # 7. Recovery Phase
        self.recoverScenario()

        # 8. Complete Phase
        self.state_machine.transition_to(AttackScenarioStateEnum.COMPLETED)
        self.status.currentState = AttackScenarioStateEnum.COMPLETED
        self.result.finalState = "COMPLETED"
        self.result.endTime = datetime.now(timezone.utc).isoformat()
        self.result.durationSeconds = float(self.scenario.durationSeconds)

        # 9. Auto-Export Results
        self.exportScenarioResults()
        return self.result

    def resetScenario(self):
        self.scenario = None
        self.state_machine = None
        self.status = None
        self.result = None
        self._emitted_events.clear()
        self._is_paused = False

    def getScenarioState(self) -> Optional[str]:
        return self.status.currentState.value if self.status else None

    def exportScenarioResults(self) -> Path:
        if not self.result:
            raise ValueError("No scenario results to export.")
        out_file = self.export_dir / f"{self.result.runId}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(self.result.model_dump(), f, indent=2)
        return out_file

attack_scenario_runner = AttackScenarioRunner()