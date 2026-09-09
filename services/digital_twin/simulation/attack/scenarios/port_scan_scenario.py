import random
from typing import List
from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioCategoryEnum, AttackScenarioSeverityEnum,
    ScenarioPrecondition, ScenarioTrafficPattern, ExpectedIndicator, ScenarioRecoveryConfig
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from services.digital_twin.simulation.attack.framework.base_attack_scenario import BaseAttackScenario

class PortScanAttackScenario(BaseAttackScenario):
    """Canonical implementation of a Reconnaissance / Port Sweep scenario."""

    @classmethod
    def create_canonical(cls, source_dev: str = "client-01", target_dev: str = "web-01") -> "PortScanAttackScenario":
        definition = AttackScenarioModel(
            scenarioId="SCN-PORTSCAN-001",
            name="TCP Synthetic SYN Port Sweep",
            category=AttackScenarioCategoryEnum.PORT_SCAN,
            description="Simulates horizontal port scanning across privileged and unallocated TCP ports.",
            sourceDevice=source_dev,
            targetDevice=target_dev,
            severity=AttackScenarioSeverityEnum.MEDIUM,
            durationSeconds=10,
            preconditions=ScenarioPrecondition(
                targetDevice=target_dev,
                targetOnline=True,
                requiredOpenPorts=[80, 443],
                requiredClosedPorts=[21, 23, 25]
            ),
            trafficPattern=ScenarioTrafficPattern(
                patternType="SWEEP",
                protocol="TCP",
                intensityMultiplier=1.0,
                parameters={"ports": [21, 22, 23, 25, 80, 110, 443, 8080, 8443]}
            ),
            expectedIndicators=[
                ExpectedIndicator(
                    indicatorType="PORT_SPREAD_ANOMALY",
                    thresholdMetric="unique_ports_contacted",
                    expectedThreshold=5.0,
                    description="Client contacts > 5 distinct ports within 10 seconds"
                )
            ],
            recovery=ScenarioRecoveryConfig(
                autoRecover=True,
                resetSocketConnections=True
            )
        )
        return cls(definition)

    def generate_traffic_events(self) -> List[UnifiedTrafficEventModel]:
        ports = self.definition.trafficPattern.parameters.get("ports", [80, 443])
        events: List[UnifiedTrafficEventModel] = []
        rng = random.Random(12345)

        for p in ports:
            src_port = rng.randint(49152, 65535)
            events.append(UnifiedTrafficEventModel(
                simulationId=self.status.runId,
                sourceDevice=self.definition.sourceDevice,
                destinationDevice=self.definition.targetDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port,
                destinationPort=p,
                bytes=60,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.CONNECTING,
                details={"scenario": self.definition.scenarioId, "flag": "SYN"}
            ))
        return events

    def evaluate_indicators(self, events: List[UnifiedTrafficEventModel]) -> List[str]:
        unique_ports = {e.destinationPort for e in events if e.destinationPort is not None}
        observed = []
        for ind in self.definition.expectedIndicators:
            if ind.indicatorType == "PORT_SPREAD_ANOMALY" and len(unique_ports) >= ind.expectedThreshold:
                observed.append(ind.indicatorType)
        return observed

    def recover(self):
        # Reset any temporary sockets or port modifications
        pass