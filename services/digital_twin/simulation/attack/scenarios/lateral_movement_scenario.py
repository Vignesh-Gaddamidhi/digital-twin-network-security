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

class LateralMovementScenario(BaseAttackScenario):
    """
    Day 77: SCN-LATERAL-001
    Simulates multi-hop lateral pivot progression across the network topology:
    CLIENT-01 (SSH:22) -> SERVER-01 (SMB:445) -> SERVER-02 (Postgres:5432) -> DB-01.
    """

    HOP_CHAIN = [
        {"src": "CLIENT-01", "dst": "SERVER-01", "port": 22,   "proto": "TCP", "label": "SSH_PIVOT"},
        {"src": "SERVER-01", "dst": "SERVER-02", "port": 445,  "proto": "TCP", "label": "SMB_REMOTE_ADMIN"},
        {"src": "SERVER-02", "dst": "DB-01",     "port": 5432, "proto": "TCP", "label": "DATABASE_ACCESS"},
    ]

    def __init__(
        self,
        source_device: str = "CLIENT-01",
        intermediate_1: str = "SERVER-01",
        intermediate_2: str = "SERVER-02",
        destination_target: str = "DB-01",
        seed: int = 12345
    ):
        self.seed = seed
        self.source_device = source_device
        self.intermediate_1 = intermediate_1
        self.intermediate_2 = intermediate_2
        self.destination_target = destination_target
        self._rng = random.Random(seed)
        self.generated_packets: List[UnifiedTrafficEventModel] = []

        scenario_def = AttackScenarioModel(
            scenarioId="SCN-LATERAL-001",
            name="Synthetic Lateral Connection Pattern",
            category=AttackScenarioCategoryEnum.LATERAL_MOVEMENT,
            description=f"Simulates multi-hop east-west pivot progression: {source_device} -> {intermediate_1} -> {intermediate_2} -> {destination_target}.",
            sourceDevice=source_device,
            targetDevice=intermediate_1,
            severity=AttackScenarioSeverityEnum.HIGH,
            durationSeconds=6,
            preconditions=ScenarioPrecondition(
                targetDevice=intermediate_1,
                targetOnline=True,
                networkReachabilityRequired=True
            ),
            preconditionRules=[
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=source_device,
                    expectedValue=True,
                    description=f"Origin device {source_device} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=intermediate_1,
                    expectedValue=True,
                    description=f"First jump host {intermediate_1} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=intermediate_2,
                    expectedValue=True,
                    description=f"Second jump host {intermediate_2} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.DEVICE_EXISTS,
                    target=destination_target,
                    expectedValue=True,
                    description=f"Destination asset {destination_target} must exist"
                )
            ],
            trafficPattern=ScenarioTrafficPattern(
                patternType="SEQUENTIAL",
                protocol="TCP",
                intensityMultiplier=1.2,
                parameters={"hops": 3, "chain": [source_device, intermediate_1, intermediate_2, destination_target]}
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="UNUSUAL_DEVICE_SEQUENCE",
                    thresholdMetric="traversed_host_chain_length",
                    expectedThreshold=3.0,
                    direction="GREATER_THAN",
                    description="Sequential connection sequence traverses >= 4 unique hosts"
                ),
                ExpectedIndicator(
                    indicatorType="NEW_INTERNAL_CONNECTION",
                    thresholdMetric="internal_connections_count",
                    expectedThreshold=2.0,
                    direction="GREATER_THAN",
                    description="Novel internal east-west connection links established (> 2)"
                ),
                ExpectedIndicator(
                    indicatorType="MULTI_HOST_CONNECTION_PATTERN",
                    thresholdMetric="multi_host_hop_count",
                    expectedThreshold=2.0,
                    direction="GREATER_THAN",
                    description="Distinct hops generating onward connection attempts > 2"
                ),
                ExpectedIndicator(
                    indicatorType="UNUSUAL_DESTINATION",
                    thresholdMetric="reaches_database_tier",
                    expectedThreshold=0.5,
                    direction="GREATER_THAN",
                    description="Connection path terminates on internal high-value database"
                ),
                ExpectedIndicator(
                    indicatorType="INCREASED_INTERNAL_CONNECTIONS",
                    thresholdMetric="internal_connections_count",
                    expectedThreshold=2.0,
                    direction="GREATER_THAN",
                    description="Internal session propagation rate increases"
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

        hops = [
            {"src": self.source_device,    "dst": self.intermediate_1,   "port": 22,   "label": "SSH_HOP"},
            {"src": self.intermediate_1,   "dst": self.intermediate_2,   "port": 445,  "label": "SMB_HOP"},
            {"src": self.intermediate_2,   "dst": self.destination_target, "port": 5432, "label": "DB_HOP"}
        ]

        for step_idx, hop in enumerate(hops):
            offset = float(step_idx) * 1.5
            req_ts = (base_t + timedelta(seconds=offset)).isoformat()
            resp_ts = (base_t + timedelta(seconds=offset + 0.06)).isoformat()
            src_port = 50000 + (step_idx * 100)

            # 1. Forward Hop Packet
            fwd_pkt = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=hop["src"],
                destinationDevice=hop["dst"],
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port,
                destinationPort=hop["port"],
                bytes=256,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                timestamp=req_ts,
                details={
                    "scenarioId": "SCN-LATERAL-001",
                    "lateral_step": step_idx + 1,
                    "hop_label": hop["label"],
                    "chain_stage": f"{hop['src']}->{hop['dst']}"
                }
            )
            self.generated_packets.append(fwd_pkt)

            # 2. Response / ACK Packet
            ack_pkt = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=hop["dst"],
                destinationDevice=hop["src"],
                protocol=TransportProtocolEnum.TCP,
                sourcePort=hop["port"],
                destinationPort=src_port,
                bytes=128,
                packets=1,
                direction=TrafficDirectionEnum.INBOUND,
                tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                timestamp=resp_ts,
                details={
                    "scenarioId": "SCN-LATERAL-001",
                    "lateral_step": step_idx + 1,
                    "status": "HOP_ESTABLISHED"
                }
            )
            self.generated_packets.append(ack_pkt)

            # Record active session in Twin State Engine
            try:
                network_state_engine.createConnectionState(ActiveConnectionSessionModel(
                    id=f"lat-sess-hop{step_idx+1}",
                    source=hop["src"],
                    destination=hop["dst"],
                    protocol="TCP",
                    sourcePort=src_port,
                    destinationPort=hop["port"],
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
        affected = [self.source_device, self.intermediate_1, self.intermediate_2, self.destination_target]
        plan = ScenarioRecoveryPlan(
            scenarioId=self.definition.scenarioId,
            strategy=RecoveryStrategyEnum.RESTORE_BASELINE,
            durationSeconds=2.0,
            affectedDevices=affected,
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

        affected = [self.source_device, self.intermediate_1, self.intermediate_2, self.destination_target]

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
            affectedDevices=affected,
            stateChanges={
                "lateral_path": f"{self.source_device} -> {self.intermediate_1} -> {self.intermediate_2} -> {self.destination_target}",
                "total_hops": 3,
                "terminal_target": self.destination_target,
                "traversed_ports": [22, 445, 5432]
            },
            recoveryStatus="VERIFIED_RESTORED",
            recoveryVerified=True,
            finalState=exec_status.currentState.value
        )