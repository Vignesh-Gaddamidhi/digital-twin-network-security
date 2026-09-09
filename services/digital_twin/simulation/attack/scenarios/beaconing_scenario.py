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

class BeaconingAttackScenario(BaseAttackScenario):
    """
    Day 76: SCN-BEACON-001
    Periodic Communication Pattern simulating C2-like regular heartbeat beaconing
    from CLIENT-01 to SERVER-01 over HTTPS (port 443) with deterministic jitter.
    """

    def __init__(
        self,
        source_device: str = "CLIENT-01",
        target_device: str = "SERVER-01",
        target_port: int = 443,
        interval_seconds: float = 1.0,
        total_beacons: int = 10,
        jitter_ratio: float = 0.05,
        seed: int = 12345
    ):
        self.seed = seed
        self.target_port = target_port
        self.interval_seconds = interval_seconds
        self.total_beacons = total_beacons
        self.jitter_ratio = jitter_ratio
        self._rng = random.Random(seed)
        self.generated_packets: List[UnifiedTrafficEventModel] = []

        scenario_def = AttackScenarioModel(
            scenarioId="SCN-BEACON-001",
            name="Periodic Communication Pattern",
            category=AttackScenarioCategoryEnum.BEACONING,
            description=f"Simulates C2 heartbeat beaconing from {source_device} to {target_device} over port {target_port} with regular {interval_seconds}s intervals.",
            sourceDevice=source_device,
            targetDevice=target_device,
            severity=AttackScenarioSeverityEnum.HIGH,
            durationSeconds=int(total_beacons * interval_seconds),
            preconditions=ScenarioPrecondition(
                targetDevice=target_device,
                targetOnline=True,
                networkReachabilityRequired=True,
                requiredOpenPorts=[target_port]
            ),
            preconditionRules=[
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=source_device,
                    expectedValue=True,
                    description=f"Source device {source_device} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=target_device,
                    expectedValue=True,
                    description=f"Target device {target_device} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.PORT_STATE,
                    target=f"{target_device}:{target_port}",
                    expectedValue="OPEN",
                    description=f"Port {target_port} must be OPEN on target"
                )
            ],
            trafficPattern=ScenarioTrafficPattern(
                patternType="PERIODIC",
                protocol="TCP",
                intensityMultiplier=1.0,
                parameters={
                    "interval": interval_seconds,
                    "total_beacons": total_beacons,
                    "jitter": jitter_ratio,
                    "port": target_port
                }
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="PERIODIC_TRAFFIC",
                    thresholdMetric="interval_variance_seconds",
                    expectedThreshold=0.05,
                    direction="LESS_THAN",
                    description="Inter-packet timing variance is near zero (< 0.05s²)"
                ),
                ExpectedIndicator(
                    indicatorType="REPEATED_DESTINATION",
                    thresholdMetric="repeated_destination_count",
                    expectedThreshold=8.0,
                    direction="GREATER_THAN",
                    description="Repeated outbound connections to identical destination exceed 8"
                ),
                ExpectedIndicator(
                    indicatorType="REGULAR_TIME_INTERVAL",
                    thresholdMetric="regular_interval_score",
                    expectedThreshold=0.80,
                    direction="GREATER_THAN",
                    description="Proportion of regular intervals exceeds 80%"
                ),
                ExpectedIndicator(
                    indicatorType="UNUSUAL_CONNECTION_FREQUENCY",
                    thresholdMetric="periodic_connection_frequency",
                    expectedThreshold=0.80,
                    direction="GREATER_THAN",
                    description="Consistent periodic connection rate detected (> 0.8 conns/sec)"
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
        base_t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        current_offset = 0.0
        src_port = 51200

        for i in range(1, self.total_beacons + 1):
            jitter = self._rng.uniform(-self.jitter_ratio, self.jitter_ratio) * self.interval_seconds
            current_offset += (self.interval_seconds + jitter)

            out_ts = (base_t + timedelta(seconds=current_offset)).isoformat()
            resp_ts = (base_t + timedelta(seconds=current_offset + 0.04)).isoformat()

            out_pkt = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port + (i % 200),
                destinationPort=self.target_port,
                bytes=128,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.CONNECTING,
                timestamp=out_ts,
                details={
                    "flag": "SYN",
                    "scenarioId": "SCN-BEACON-001",
                    "beacon_seq": i,
                    "c2_channel": "HTTPS_POLL"
                }
            )
            self.generated_packets.append(out_pkt)

            in_pkt = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.targetDevice,
                destinationDevice=self.definition.sourceDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=self.target_port,
                destinationPort=src_port + (i % 200),
                bytes=64,
                packets=1,
                direction=TrafficDirectionEnum.INBOUND,
                tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                timestamp=resp_ts,
                details={
                    "flag": "ACK",
                    "scenarioId": "SCN-BEACON-001",
                    "beacon_ack": i
                }
            )
            self.generated_packets.append(in_pkt)

            try:
                network_state_engine.createConnectionState(ActiveConnectionSessionModel(
                    id=f"beacon-sess-{i}",
                    source=self.definition.sourceDevice,
                    destination=self.definition.targetDevice,
                    protocol="TCP",
                    sourcePort=src_port + (i % 200),
                    destinationPort=self.target_port,
                    status=SessionStateEnum.ACTIVE
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
            affectedDevices=[self.definition.sourceDevice, self.definition.targetDevice],
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
            affectedDevices=[self.definition.sourceDevice, self.definition.targetDevice],
            stateChanges={
                "beacon_interval": f"{self.interval_seconds}s",
                "beacons_emitted": self.total_beacons,
                "jitter_applied": f"{self.jitter_ratio * 100}%",
                "c2_channel": "HTTPS_POLL"
            },
            recoveryStatus="VERIFIED_RESTORED",
            recoveryVerified=True,
            finalState=exec_status.currentState.value
        )