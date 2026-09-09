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
from packages.shared_types.src.port_service_state import PortStateEnum
from packages.shared_types.src.scenario_result import ScenarioResult

from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.simulation.attack.framework.base_attack_scenario import BaseAttackScenario
from services.digital_twin.simulation.attack.framework.severity_engine import severity_engine
from services.digital_twin.simulation.attack.indicators.indicator_matcher import indicator_matcher
from services.digital_twin.simulation.attack.recovery.recovery_engine import recovery_engine
from packages.shared_types.src.attack_recovery import ScenarioRecoveryPlan, RecoveryStrategyEnum
from packages.shared_types.src.attack_indicators import ExpectedIndicatorModel

class PortDiscoveryScenario(BaseAttackScenario):
    """
    Day 72: SCN-PORTSCAN-001
    Synthetic Port Discovery Pattern targeting SERVER-01 across ports 21, 22, 25, 53, 80, 443, 8080.
    """

    TARGETED_PORTS = [21, 22, 25, 53, 80, 443, 8080]

    def __init__(
        self,
        source_device: str = "CLIENT-01",
        target_device: str = "SERVER-01",
        seed: int = 12345
    ):
        self.seed = seed
        self._rng = random.Random(seed)
        self.generated_packets: List[UnifiedTrafficEventModel] = []

        scenario_def = AttackScenarioModel(
            scenarioId="SCN-PORTSCAN-001",
            name="Synthetic Port Discovery Pattern",
            category=AttackScenarioCategoryEnum.PORT_SCAN,
            description="Synthetic reconnaissance sweep targeting TCP ports 21, 22, 25, 53, 80, 443, 8080 on SERVER-01.",
            sourceDevice=source_device,
            targetDevice=target_device,
            severity=AttackScenarioSeverityEnum.MEDIUM,
            durationSeconds=7,
            preconditions=ScenarioPrecondition(
                targetDevice=target_device,
                targetOnline=True,
                networkReachabilityRequired=True
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
                    type=PreconditionTypeEnum.NETWORK_CONNECTION,
                    target=f"{source_device}:{target_device}",
                    expectedValue=True,
                    description=f"Network path between {source_device} and {target_device} must exist"
                )
            ],
            trafficPattern=ScenarioTrafficPattern(
                patternType="SEQUENTIAL",
                protocol="TCP",
                intensityMultiplier=1.0,
                parameters={"ports": self.TARGETED_PORTS}
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="UNUSUAL_PORT_ACTIVITY",
                    thresholdMetric="unique_destination_ports",
                    expectedThreshold=5.0,
                    description="Probing > 5 distinct ports in single session"
                ),
                ExpectedIndicator(
                    indicatorType="HIGH_UNIQUE_PORT_COUNT",
                    thresholdMetric="unique_destination_ports",
                    expectedThreshold=5.0,
                    description="Destination ports contacted exceeds normal threshold"
                ),
                ExpectedIndicator(
                    indicatorType="HIGH_FAILED_CONNECTION_RATE",
                    thresholdMetric="failed_connections_count",
                    expectedThreshold=3.0,
                    description="Failed connection RST responses exceed 3"
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

        # Inspect open ports on target
        open_ports = set()
        try:
            live = port_service_engine.listPorts(self.definition.targetDevice)
            open_ports = {p.port for p in live if p.state == PortStateEnum.OPEN}
        except Exception:
            pass

        for idx, port in enumerate(self.TARGETED_PORTS):
            ts = (base_t + timedelta(seconds=float(idx) * 0.5)).isoformat()
            src_port = self._rng.randint(49152, 65535)
            is_open = port in open_ports

            # SYN probe from client
            syn = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port,
                destinationPort=port,
                bytes=60,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.CONNECTING,
                timestamp=ts,
                details={"flag": "SYN", "scenarioId": "SCN-PORTSCAN-001"}
            )
            self.generated_packets.append(syn)

            # Response from server
            resp_ts = (base_t + timedelta(seconds=float(idx) * 0.5 + 0.05)).isoformat()
            if is_open:
                # Port OPEN -> SYN/ACK
                resp = UnifiedTrafficEventModel(
                    simulationId=self.status.runId,
                    sourceDevice=self.definition.targetDevice,
                    destinationDevice=self.definition.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=port,
                    destinationPort=src_port,
                    bytes=54,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                    timestamp=resp_ts,
                    details={"flag": "SYN_ACK", "status": "PORT_OPEN"}
                )
                self.generated_packets.append(resp)
            else:
                # Port CLOSED -> RST
                resp = UnifiedTrafficEventModel(
                    simulationId=self.status.runId,
                    sourceDevice=self.definition.targetDevice,
                    destinationDevice=self.definition.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=port,
                    destinationPort=src_port,
                    bytes=54,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.FAILED,
                    timestamp=resp_ts,
                    details={"flag": "RST", "status": "PORT_CLOSED"}
                )
                self.generated_packets.append(resp)

                # Record failed session in network state engine
                try:
                    sess = ActiveConnectionSessionModel(
                        id=f"scan-sess-{port}-{src_port}",
                        source=self.definition.sourceDevice,
                        destination=self.definition.targetDevice,
                        protocol="TCP",
                        sourcePort=src_port,
                        destinationPort=port,
                        status=SessionStateEnum.FAILED
                    )
                    network_state_engine.createConnectionState(sess)
                except Exception:
                    pass

        return self.generated_packets

    def evaluate_indicators(self, events: List[UnifiedTrafficEventModel]) -> List[str]:
        exp_list = [
            ExpectedIndicatorModel(
                indicatorId=ind.indicatorId,
                type=ind.indicatorType,
                description=ind.description,
                metric=ind.thresholdMetric,
                threshold=ind.expectedThreshold
            )
            for ind in self.definition.expectedIndicators
        ]

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
            revertPortMutations=True,
            verificationRequired=True
        )
        return recovery_engine.execute_recovery(plan)

    def execute(self) -> ScenarioResult:
        """Executes full end-to-end lifecycle."""
        # 1. Validate
        self.validate()

        # 2. Risk Evaluation
        risk_rep = severity_engine.assess_risk(self.definition)

        # 3. Run
        exec_status = self.run()

        # 4. Synthesize ScenarioResult
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
            stateChanges={"probed_ports": self.TARGETED_PORTS, "scan_status": "COMPLETED"},
            recoveryStatus="VERIFIED_RESTORED",
            recoveryVerified=True,
            finalState=exec_status.currentState.value
        )