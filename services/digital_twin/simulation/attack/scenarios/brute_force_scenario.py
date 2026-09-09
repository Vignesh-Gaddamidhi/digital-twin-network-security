import random
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioCategoryEnum, AttackScenarioSeverityEnum,
    ScenarioPrecondition, ScenarioTrafficPattern, ExpectedIndicator, ScenarioRecoveryConfig
)
from packages.shared_types.src.preconditions import (
    PreconditionRuleModel, PreconditionTypeEnum
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from packages.shared_types.src.auth_simulation import (
    SimulatedAuthEvent, AuthEventTypeEnum
)
from packages.shared_types.src.network_state import (
    ActiveConnectionSessionModel, SessionStateEnum
)
from packages.shared_types.src.scenario_result import ScenarioResult

from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.simulation.attack.framework.base_attack_scenario import BaseAttackScenario
from services.digital_twin.simulation.attack.framework.severity_engine import severity_engine
from services.digital_twin.simulation.attack.indicators.indicator_matcher import indicator_matcher
from services.digital_twin.simulation.attack.recovery.recovery_engine import recovery_engine
from packages.shared_types.src.attack_recovery import ScenarioRecoveryPlan, RecoveryStrategyEnum
from packages.shared_types.src.attack_indicators import ExpectedIndicatorModel, IndicatorDirectionEnum

class BruteForceAttackScenario(BaseAttackScenario):
    """
    Day 73: SCN-BRUTEFORCE-001
    Repeated Authentication Failure Simulation targeting SSH/Auth service on SERVER-01.
    """

    def __init__(
        self,
        source_device: str = "CLIENT-01",
        target_device: str = "SERVER-01",
        target_account: str = "admin",
        total_attempts: int = 12,
        succeed_at_end: bool = True,
        seed: int = 12345
    ):
        self.seed = seed
        self.target_account = target_account
        self.total_attempts = total_attempts
        self.succeed_at_end = succeed_at_end
        self._rng = random.Random(seed)
        self.generated_packets: List[UnifiedTrafficEventModel] = []
        self.auth_audit_log: List[SimulatedAuthEvent] = []

        scenario_def = AttackScenarioModel(
            scenarioId="SCN-BRUTEFORCE-001",
            name="Repeated Authentication Failure Simulation",
            category=AttackScenarioCategoryEnum.BRUTE_FORCE,
            description=f"Simulates rapid authentication failures targeting {target_account} on {target_device} over SSH.",
            sourceDevice=source_device,
            targetDevice=target_device,
            severity=AttackScenarioSeverityEnum.HIGH,
            durationSeconds=3,
            preconditions=ScenarioPrecondition(
                targetDevice=target_device,
                targetOnline=True,
                networkReachabilityRequired=True,
                requiredOpenPorts=[22]
            ),
            preconditionRules=[
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=target_device,
                    expectedValue=True,
                    description=f"Target device {target_device} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.SERVICE_EXISTS,
                    target=target_device,
                    expectedValue="SSH",
                    description="Authentication service SSH must be present"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.PORT_STATE,
                    target=f"{target_device}:22",
                    expectedValue="OPEN",
                    description="Port 22 must be in OPEN state"
                )
            ],
            trafficPattern=ScenarioTrafficPattern(
                patternType="REPEATED",
                protocol="TCP",
                intensityMultiplier=1.5,
                parameters={"service": "SSH", "port": 22, "attempts": total_attempts}
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="HIGH_AUTH_FAILURE_RATE",
                    thresholdMetric="auth_failure_rate_per_sec",
                    expectedThreshold=3.0,
                    description="Failed attempts exceed 3 per second"
                ),
                ExpectedIndicator(
                    indicatorType="REPEATED_AUTH_FAILURES",
                    thresholdMetric="auth_failures_total",
                    expectedThreshold=8.0,
                    description="Total consecutive failed attempts exceed 8"
                ),
                ExpectedIndicator(
                    indicatorType="SHORT_FAILURE_INTERVAL",
                    thresholdMetric="mean_auth_failure_interval",
                    expectedThreshold=0.5,
                    direction="LESS_THAN",
                    description="Mean inter-arrival delay is less than 0.5 seconds"
                ),
                ExpectedIndicator(
                    indicatorType="UNUSUAL_AUTH_PATTERN",
                    thresholdMetric="auth_failure_ratio",
                    expectedThreshold=0.85,
                    description="Failure-to-total-attempt ratio exceeds 85%"
                )
            ],
            recovery=ScenarioRecoveryConfig(
                autoRecover=True,
                resetSocketConnections=True,
                restoreTraffic=True,
                revertPortMutations=True
            )
        )
        super().__init__(scenario_def)

    def generate_traffic_events(self) -> List[UnifiedTrafficEventModel]:
        self.generated_packets.clear()
        self.auth_audit_log.clear()
        base_t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        src_port = 52340

        for i in range(1, self.total_attempts + 1):
            offset_sec = float(i - 1) * 0.20  # Fast 200ms repetition interval
            attempt_time = (base_t + timedelta(seconds=offset_sec)).isoformat()
            resp_time = (base_t + timedelta(seconds=offset_sec + 0.08)).isoformat()

            # Determine whether this attempt fails or succeeds
            is_final_attempt = (i == self.total_attempts)
            is_success = is_final_attempt and self.succeed_at_end

            # 1. Outbound AUTH_ATTEMPT packet
            req_pkt = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port + i,
                destinationPort=22,
                bytes=128,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                timestamp=attempt_time,
                details={
                    "subsystem": "AUTH",
                    "auth_event": "AUTH_ATTEMPT",
                    "username": self.target_account,
                    "attempt": i
                }
            )
            self.generated_packets.append(req_pkt)

            # Record in auth audit log
            self.auth_audit_log.append(SimulatedAuthEvent(
                scenarioId=self.definition.scenarioId,
                sourceDevice=self.definition.sourceDevice,
                targetDevice=self.definition.targetDevice,
                service="SSH",
                port=22,
                username=self.target_account,
                eventType=AuthEventTypeEnum.AUTH_ATTEMPT,
                attemptNumber=i,
                timestamp=attempt_time
            ))

            # 2. Inbound Target Response
            if is_success:
                resp_pkt = UnifiedTrafficEventModel(
                    simulationId=self.status.runId,
                    sourceDevice=self.definition.targetDevice,
                    destinationDevice=self.definition.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=22,
                    destinationPort=src_port + i,
                    bytes=256,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                    timestamp=resp_time,
                    details={
                        "subsystem": "AUTH",
                        "auth_event": "AUTH_SUCCESS",
                        "username": self.target_account,
                        "status": "AUTHENTICATED"
                    }
                )
                self.generated_packets.append(resp_pkt)
                self.auth_audit_log.append(SimulatedAuthEvent(
                    scenarioId=self.definition.scenarioId,
                    sourceDevice=self.definition.sourceDevice,
                    targetDevice=self.definition.targetDevice,
                    service="SSH",
                    port=22,
                    username=self.target_account,
                    eventType=AuthEventTypeEnum.AUTH_SUCCESS,
                    attemptNumber=i,
                    timestamp=resp_time
                ))
            else:
                resp_pkt = UnifiedTrafficEventModel(
                    simulationId=self.status.runId,
                    sourceDevice=self.definition.targetDevice,
                    destinationDevice=self.definition.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=22,
                    destinationPort=src_port + i,
                    bytes=84,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.FAILED,
                    timestamp=resp_time,
                    details={
                        "subsystem": "AUTH",
                        "auth_event": "AUTH_FAILURE",
                        "username": self.target_account,
                        "reason": "Simulated authentication credentials rejected"
                    }
                )
                self.generated_packets.append(resp_pkt)
                self.auth_audit_log.append(SimulatedAuthEvent(
                    scenarioId=self.definition.scenarioId,
                    sourceDevice=self.definition.sourceDevice,
                    targetDevice=self.definition.targetDevice,
                    service="SSH",
                    port=22,
                    username=self.target_account,
                    eventType=AuthEventTypeEnum.AUTH_FAILURE,
                    failureReason="Simulated authentication credentials rejected",
                    attemptNumber=i,
                    timestamp=resp_time
                ))

                # Inject failed session tracking into twin
                try:
                    network_state_engine.createConnectionState(ActiveConnectionSessionModel(
                        id=f"auth-fail-sess-{i}",
                        source=self.definition.sourceDevice,
                        destination=self.definition.targetDevice,
                        protocol="TCP",
                        sourcePort=src_port + i,
                        destinationPort=22,
                        status=SessionStateEnum.FAILED
                    ))
                except Exception:
                    pass

        return self.generated_packets

    def evaluate_indicators(self, events: List[UnifiedTrafficEventModel]) -> List[str]:
        exp_list = []
        for ind in self.definition.expectedIndicators:
            dir_enum = IndicatorDirectionEnum.LESS_THAN if getattr(ind, "direction", "GREATER_THAN") == "LESS_THAN" else IndicatorDirectionEnum.GREATER_THAN
            exp_list.append(ExpectedIndicatorModel(
                indicatorId=ind.indicatorId,
                type=ind.indicatorType,
                description=ind.description,
                metric=ind.thresholdMetric,
                threshold=ind.expectedThreshold,
                direction=dir_enum
            ))

        report = indicator_matcher.verify_scenario_indicators(
            scenario_id=self.definition.scenarioId,
            expected_indicators=exp_list,
            events=events,
            duration_seconds=float(self.definition.durationSeconds)
        )
        return [m.type.value for m in report.matchedIndicators]

    def recover(self):
        plan = ScenarioRecoveryPlan(
            scenarioId=self.definition.scenarioId,
            strategy=RecoveryStrategyEnum.RESTORE_BASELINE,
            durationSeconds=2.0,
            affectedDevices=[self.definition.targetDevice],
            restoreConnections=True,
            restoreTraffic=True,
            verificationRequired=True
        )
        return recovery_engine.execute_recovery(plan)

    def execute(self) -> ScenarioResult:
        self.validate()
        risk_rep = severity_engine.assess_risk(self.definition)
        exec_status = self.run()
        total_bytes = sum(p.bytes for p in self.generated_packets)

        return ScenarioResult(
            scenarioId=self.definition.scenarioId,
            runId=exec_status.runId,
            startTime=exec_status.startedAt,
            endTime=exec_status.updatedAt,
            durationSeconds=float(self.definition.durationSeconds),
            eventsGenerated=len(self.generated_packets),
            bytesGenerated=total_bytes,
            indicatorsObserved=exec_status.indicatorsObserved,
            alertsGenerated=[f"ALERT-{ind}" for ind in exec_status.indicatorsObserved],
            riskScore=risk_rep.riskScore,
            riskLevel=risk_rep.riskLevel.value,
            affectedDevices=[self.definition.targetDevice],
            stateChanges={
                "target_account": self.target_account,
                "auth_attempts": self.total_attempts,
                "terminal_event": "AUTH_SUCCESS" if self.succeed_at_end else "AUTH_FAILURE"
            },
            recoveryStatus="VERIFIED_RESTORED",
            recoveryVerified=True,
            finalState=exec_status.currentState.value
        )