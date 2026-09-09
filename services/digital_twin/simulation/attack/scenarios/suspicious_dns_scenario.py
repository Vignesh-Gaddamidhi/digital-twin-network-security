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

class SuspiciousDnsScenario(BaseAttackScenario):
    """
    Day 75: SCN-DNS-001
    Suspicious DNS Behaviour Simulation targeting DNS-01 with burst queries,
    TXT record clustering, repeated lookups, and subdomain entropy using .test domains.
    """

    DOMAINS = [
        "service.test",
        "internal.test",
        "example.test",
        "tunnel.random.test"
    ]

    def __init__(
        self,
        source_device: str = "CLIENT-01",
        target_device: str = "DNS-01",
        target_port: int = 53,
        total_queries: int = 60,
        seed: int = 12345
    ):
        self.seed = seed
        self.target_port = target_port
        self.total_queries = total_queries
        self._rng = random.Random(seed)
        self.generated_packets: List[UnifiedTrafficEventModel] = []

        scenario_def = AttackScenarioModel(
            scenarioId="SCN-DNS-001",
            name="Suspicious DNS Behaviour Simulation",
            category=AttackScenarioCategoryEnum.SUSPICIOUS_DNS,
            description=f"Simulates high-frequency DNS query bursts, TXT record clustering, and subdomain entropy against {target_device}.",
            sourceDevice=source_device,
            targetDevice=target_device,
            severity=AttackScenarioSeverityEnum.MEDIUM,
            durationSeconds=3,
            preconditions=ScenarioPrecondition(
                targetDevice=target_device,
                targetOnline=True,
                networkReachabilityRequired=True,
                requiredOpenPorts=[target_port]
            ),
            preconditionRules=[
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
                    description=f"Port {target_port} must be OPEN"
                )
            ],
            trafficPattern=ScenarioTrafficPattern(
                patternType="BURST",
                protocol="UDP",
                intensityMultiplier=2.5,
                parameters={"total_queries": total_queries, "port": target_port}
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="UNUSUAL_DNS_FREQUENCY",
                    thresholdMetric="dns_query_rate_per_sec",
                    expectedThreshold=10.0,
                    direction="GREATER_THAN",
                    description="DNS query rate exceeds 10 queries/second"
                ),
                ExpectedIndicator(
                    indicatorType="UNUSUAL_DNS_QUERY_TYPE",
                    thresholdMetric="dns_txt_query_ratio",
                    expectedThreshold=0.30,
                    direction="GREATER_THAN",
                    description="TXT query ratio exceeds 30% of total DNS traffic"
                ),
                ExpectedIndicator(
                    indicatorType="REPEATED_DNS_REQUESTS",
                    thresholdMetric="max_repeated_domain_count",
                    expectedThreshold=5.0,
                    direction="GREATER_THAN",
                    description="Repeated identical domain queries exceed threshold"
                ),
                ExpectedIndicator(
                    indicatorType="UNUSUAL_DNS_DISTRIBUTION",
                    thresholdMetric="unique_subdomains_count",
                    expectedThreshold=10.0,
                    direction="GREATER_THAN",
                    description="Subdomain query distribution diversity exceeds 10 unique FQDNs"
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

        # 1. 20 repeated lookups for "service.test" (A record)
        for i in range(20):
            offset = (float(i) / float(self.total_queries)) * float(self.definition.durationSeconds)
            ts = (base_t + timedelta(seconds=offset)).isoformat()
            src_port = 53000 + (i % 500)
            
            # Query
            self.generated_packets.append(UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.UDP,
                sourcePort=src_port,
                destinationPort=self.target_port,
                bytes=68,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                timestamp=ts,
                details={
                    "app": "DNS",
                    "dns_domain": "service.test",
                    "dns_record_type": "A",
                    "scenarioId": "SCN-DNS-001"
                }
            ))

        # 2. 25 TXT record queries (modeling tunneling / data encoding pattern)
        for i in range(25):
            offset = (float(20 + i) / float(self.total_queries)) * float(self.definition.durationSeconds)
            ts = (base_t + timedelta(seconds=offset)).isoformat()
            src_port = 54000 + i
            subdomain = f"data-chunk-{i:03d}.tunnel.random.test"

            self.generated_packets.append(UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.UDP,
                sourcePort=src_port,
                destinationPort=self.target_port,
                bytes=240,  # Larger payload for TXT data query
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                timestamp=ts,
                details={
                    "app": "DNS",
                    "dns_domain": subdomain,
                    "dns_record_type": "TXT",
                    "scenarioId": "SCN-DNS-001"
                }
            ))

        # 3. 15 diverse subdomain probes (internal.test & random.test)
        for i in range(15):
            offset = (float(45 + i) / float(self.total_queries)) * float(self.definition.durationSeconds)
            ts = (base_t + timedelta(seconds=offset)).isoformat()
            src_port = 55000 + i
            subdomain = f"node-{i}.internal.test"

            self.generated_packets.append(UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.UDP,
                sourcePort=src_port,
                destinationPort=self.target_port,
                bytes=72,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                timestamp=ts,
                details={
                    "app": "DNS",
                    "dns_domain": subdomain,
                    "dns_record_type": "A",
                    "scenarioId": "SCN-DNS-001"
                }
            ))

        # Mutate digital twin metrics on DNS-01
        performance_state_engine.updateCpu(self.definition.targetDevice, 45.0, source="DNS_SURGE")
        network_state_engine.updateNetworkMetrics(
            device_id=self.definition.targetDevice,
            network_utilisation=65.0,
            bytes_sent=0,
            bytes_received=sum(p.bytes for p in self.generated_packets),
            packets_sent=0,
            packets_received=len(self.generated_packets)
        )

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
                "dns_query_count": len(self.generated_packets),
                "peak_network_utilisation": "65.0%",
                "monitored_domains": self.DOMAINS
            },
            recoveryStatus="VERIFIED_RESTORED",
            recoveryVerified=True,
            finalState=exec_status.currentState.value
        )