import random
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timezone

from packages.shared_types.src.connection_anomaly import (
    ConnectionAnomalyProfile, ConnectionLifecycleStateEnum,
    ConnectionAnomalyPatternEnum, LifecycleStateBreakdown, ConnectionAnomalyRunResult
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from packages.shared_types.src.network_state import (
    ActiveConnectionSessionModel, SessionStateEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.network_state_engine import network_state_engine

class ConnectionAnomalyEngine:
    """Simulates unusual connection behaviour across progressive scaling tiers (5, 10, 20, 50, 100)."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random(443322)

    def _auto_provision(self, src: str, dst: str, port: int):
        from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
        if not device_registry.getDevice(src):
            device_registry.createDevice(NetworkDeviceModel(id=src, hostname=src.upper(), type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL))
        if not device_registry.getDevice(dst):
            device_registry.createDevice(NetworkDeviceModel(id=dst, hostname=dst.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[port]))

    def runAnomalyScenario(
        self,
        profile: ConnectionAnomalyProfile,
        sync_to_twin: bool = True,
        simulation_id: str = "sim-conn-anom-01"
    ) -> ConnectionAnomalyRunResult:
        self._auto_provision(profile.affectedDevice, profile.targetDevice, profile.targetPort)

        # Connection scaling ladder
        tiers = [5, 10, 20, 50, 100]
        tiers = [t for t in tiers if t <= profile.abnormalConnectionRate]
        if profile.abnormalConnectionRate not in tiers:
            tiers.append(profile.abnormalConnectionRate)

        new_total = 0
        est_total = 0
        closed_total = 0
        failed_total = 0

        raw_packets: List[UnifiedTrafficEventModel] = []
        now_ts = datetime.now(timezone.utc).isoformat()

        # Step through each escalation tier
        for tier in tiers:
            for _ in range(tier):
                src_port = self._rng.randint(49152, 65535)
                new_total += 1

                # Emitting SYN (NEW)
                raw_packets.append(UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=src_port,
                    destinationPort=profile.targetPort,
                    bytes=60,
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    tcpState=SimulatedTcpStateEnum.CONNECTING,
                    details={"lifecycle": "NEW"}
                ))

                if profile.lifecyclePattern == ConnectionAnomalyPatternEnum.HIGH_NEW_HIGH_FAILED:
                    # Anomaly pattern: 15% Established, 75% Failed, 10% Closed
                    outcome = self._rng.random()
                    if outcome < 0.15:
                        est_total += 1
                        closed_total += 1
                        raw_packets.append(UnifiedTrafficEventModel(
                            simulationId=simulation_id,
                            sourceDevice=profile.affectedDevice,
                            destinationDevice=profile.targetDevice,
                            protocol=TransportProtocolEnum.TCP,
                            sourcePort=src_port,
                            destinationPort=profile.targetPort,
                            bytes=54,
                            packets=1,
                            direction=TrafficDirectionEnum.OUTBOUND,
                            tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                            details={"lifecycle": "ESTABLISHED"}
                        ))
                    else:
                        failed_total += 1
                        raw_packets.append(UnifiedTrafficEventModel(
                            simulationId=simulation_id,
                            sourceDevice=profile.targetDevice,
                            destinationDevice=profile.affectedDevice,
                            protocol=TransportProtocolEnum.TCP,
                            sourcePort=profile.targetPort,
                            destinationPort=src_port,
                            bytes=54,
                            packets=1,
                            direction=TrafficDirectionEnum.INBOUND,
                            tcpState=SimulatedTcpStateEnum.FAILED,
                            details={"lifecycle": "FAILED", "flag": "RST"}
                        ))
                else:
                    est_total += 1
                    closed_total += 1

        # Synchronize with Digital Twin
        if sync_to_twin:
            # Register active and failed session models in network state engine
            for i in range(profile.normalConnectionRate):
                sess = ActiveConnectionSessionModel(
                    id=f"conn-anom-est-{i}",
                    source=profile.affectedDevice,
                    destination=profile.targetDevice,
                    protocol="TCP",
                    sourcePort=50000 + i,
                    destinationPort=profile.targetPort,
                    status=SessionStateEnum.ACTIVE
                )
                try:
                    network_state_engine.createConnectionState(sess)
                except Exception:
                    pass

            for i in range(min(failed_total, 25)):
                sess_f = ActiveConnectionSessionModel(
                    id=f"conn-anom-fail-{i}",
                    source=profile.affectedDevice,
                    destination=profile.targetDevice,
                    protocol="TCP",
                    sourcePort=55000 + i,
                    destinationPort=profile.targetPort,
                    status=SessionStateEnum.FAILED
                )
                try:
                    network_state_engine.createConnectionState(sess_f)
                except Exception:
                    pass

        summary_breakdown = LifecycleStateBreakdown(
            newCount=new_total,
            establishedCount=est_total,
            closedCount=closed_total,
            failedCount=failed_total
        )

        return ConnectionAnomalyRunResult(
            profileId=profile.profileId,
            targetDevice=profile.targetDevice,
            protocol=profile.protocol,
            destinationPort=profile.targetPort,
            classification="UNUSUAL_CONNECTION_BEHAVIOUR",
            baselineActiveConnections=profile.normalConnectionRate,
            peakActiveConnections=tiers[-1],
            lifecycleSummary=summary_breakdown,
            connectionLevelsObserved=tiers,
            totalTransactions=len(raw_packets),
            timestamp=now_ts
        )

connection_anomaly_engine = ConnectionAnomalyEngine()