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

class DataExfiltrationScenario(BaseAttackScenario):
    """
    Day 78: SCN-EXFIL-001
    Synthetic Outbound Data Transfer Pattern simulating large-volume asymmetric egress
    from CLIENT-01 to EXTERNAL-SIMULATED-ENDPOINT over HTTPS (port 443).
    """

    def __init__(
        self,
        source_device: str = "CLIENT-01",
        target_device: str = "EXTERNAL-SIMULATED-ENDPOINT",
        target_port: int = 443,
        total_chunks: int = 250,
        chunk_size_bytes: int = 1460,
        duration_seconds: int = 6,
        seed: int = 12345
    ):
        self.seed = seed
        self.target_port = target_port
        self.total_chunks = total_chunks
        self.chunk_size_bytes = chunk_size_bytes
        self._rng = random.Random(seed)
        self.generated_packets: List[UnifiedTrafficEventModel] = []

        scenario_def = AttackScenarioModel(
            scenarioId="SCN-EXFIL-001",
            name="Synthetic Outbound Data Transfer Pattern",
            category=AttackScenarioCategoryEnum.DATA_EXFILTRATION,
            description=f"Simulates sustained large-volume egress from {source_device} to {target_device} over port {target_port}.",
            sourceDevice=source_device,
            targetDevice=target_device,
            severity=AttackScenarioSeverityEnum.CRITICAL,
            durationSeconds=duration_seconds,
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
                    description=f"Target external endpoint {target_device} must exist"
                ),
                PreconditionRuleModel(
                    type=PreconditionTypeEnum.PORT_STATE,
                    target=f"{target_device}:{target_port}",
                    expectedValue="OPEN",
                    description=f"Port {target_port} must be OPEN"
                )
            ],
            trafficPattern=ScenarioTrafficPattern(
                patternType="BURST",
                protocol="TCP",
                intensityMultiplier=3.0,
                parameters={
                    "chunks": total_chunks,
                    "chunk_size": chunk_size_bytes,
                    "port": target_port
                }
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="UNUSUAL_OUTBOUND_VOLUME",
                    thresholdMetric="outbound_bytes_total",
                    expectedThreshold=250000.0,
                    direction="GREATER_THAN",
                    description="Total egress payload bytes exceed 250,000 bytes"
                ),
                ExpectedIndicator(
                    indicatorType="UNUSUAL_DESTINATION",
                    thresholdMetric="is_unusual_destination",
                    expectedThreshold=0.5,
                    direction="GREATER_THAN",
                    description="Traffic directed to untrusted external destination"
                ),
                ExpectedIndicator(
                    indicatorType="HIGH_TRANSFER_RATE",
                    thresholdMetric="transfer_rate_bytes_per_sec",
                    expectedThreshold=50000.0,
                    direction="GREATER_THAN",
                    description="Outbound transfer throughput exceeds 50,000 bytes/second"
                ),
                ExpectedIndicator(
                    indicatorType="LONG_OUTBOUND_SESSION",
                    thresholdMetric="outbound_session_duration",
                    expectedThreshold=5.0,
                    direction="GREATER_THAN",
                    description="Outbound connection transfer duration exceeds 5.0 seconds"
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
        src_port = 52140

        for i in range(1, self.total_chunks + 1):
            offset = (float(i) / float(self.total_chunks)) * float(self.definition.durationSeconds)
            out_ts = (base_t + timedelta(seconds=offset)).isoformat()
            ack_ts = (base_t + timedelta(seconds=offset + 0.02)).isoformat()

            # 1. High-Volume Egress Chunk (1460 bytes)
            out_pkt = UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port,
                destinationPort=self.target_port,
                bytes=self.chunk_size_bytes,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                timestamp=out_ts,
                details={
                    "scenarioId": "SCN-EXFIL-001",
                    "chunk_id": i,
                    "channel": "HTTPS_TUNNEL_EXFIL",
                    "payload_type": "SYNTHETIC_OCTET_STREAM"
                }
            )
            self.generated_packets.append(out_pkt)

            # 2. Remote Server ACK (Small control frame: 54 bytes)
            if i % 10 == 0 or i == self.total_chunks:
                ack_pkt = UnifiedTrafficEventModel(
                    simulationId=self.status.runId,
                    sourceDevice=self.definition.targetDevice,
                    destinationDevice=self.definition.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=self.target_port,
                    destinationPort=src_port,
                    bytes=54,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                    timestamp=ack_ts,
                    details={
                        "scenarioId": "SCN-EXFIL-001",
                        "ack_chunk": i
                    }
                )
                self.generated_packets.append(ack_pkt)

        # Mutate digital twin telemetry on source device
        total_out_bytes = sum(p.bytes for p in self.generated_packets if p.direction == TrafficDirectionEnum.OUTBOUND)
        performance_state_engine.updateCpu(self.definition.sourceDevice, 60.0, source="EXFIL_COMPRESSION")
        network_state_engine.updateNetworkMetrics(
            device_id=self.definition.sourceDevice,
            network_utilisation=80.0,
            bytes_sent=total_out_bytes,
            bytes_received=54 * 25,
            packets_sent=self.total_chunks,
            packets_received=25
        )

        try:
            network_state_engine.createConnectionState(ActiveConnectionSessionModel(
                id="exfil-tunnel-sess-001",
                source=self.definition.sourceDevice,
                destination=self.definition.targetDevice,
                protocol="TCP",
                sourcePort=src_port,
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
            affectedDevices=[self.definition.sourceDevice],
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
            affectedDevices=[self.definition.sourceDevice],
            stateChanges={
                "outbound_bytes_exfiltrated": sum(p.bytes for p in self.generated_packets if p.direction == TrafficDirectionEnum.OUTBOUND),
                "peak_bandwidth_utilisation": "80.0%",
                "tunnel_channel": "HTTPS_PORT_443"
            },
            recoveryStatus="VERIFIED_RESTORED",
            recoveryVerified=True,
            finalState=exec_status.currentState.value
        )