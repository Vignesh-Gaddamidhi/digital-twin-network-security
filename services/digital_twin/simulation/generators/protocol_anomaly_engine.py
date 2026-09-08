import random
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timezone

from packages.shared_types.src.protocol_anomaly import (
    ProtocolWindowPhaseEnum, ProtocolDistributionProfile,
    WindowProtocolStats, ProtocolAnomalyEvent, ProtocolAnomalyRunResult
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum,
    IcmpMessageTypeEnum, UnifiedTrafficEventModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry

class ProtocolAnomalyEngine:
    """Simulates protocol distribution skews across Normal -> Abnormal -> Recovery windows."""

    NORMAL_PROFILE = {
        "HTTPS": 0.60,
        "DNS": 0.20,
        "HTTP": 0.10,
        "SSH": 0.05,
        "ICMP": 0.05
    }

    ABNORMAL_PROFILE = {
        "HTTPS": 0.20,
        "DNS": 0.05,
        "HTTP": 0.05,
        "SSH": 0.05,
        "ICMP": 0.65
    }

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random(772211)
        self._history_events: List[ProtocolAnomalyEvent] = []

    def _auto_provision(self, src: str, dst: str):
        from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
        if not device_registry.getDevice(src):
            device_registry.createDevice(NetworkDeviceModel(id=src, hostname=src.upper(), type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL))
        if not device_registry.getDevice(dst):
            device_registry.createDevice(NetworkDeviceModel(id=dst, hostname=dst.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443, 53, 22]))

    def _simulate_window(
        self,
        phase: ProtocolWindowPhaseEnum,
        weights: Dict[str, float],
        duration_seconds: int,
        packets_per_second: int,
        source_dev: str,
        dest_dev: str,
        simulation_id: str
    ) -> Tuple[WindowProtocolStats, List[UnifiedTrafficEventModel]]:
        start_ts = datetime.now(timezone.utc).isoformat()
        protocols = list(weights.keys())
        w_values = list(weights.values())

        counts = {p: 0 for p in protocols}
        packets: List[UnifiedTrafficEventModel] = []
        total_pkts = duration_seconds * packets_per_second

        for sec in range(duration_seconds):
            for _ in range(packets_per_second):
                chosen_proto = self._rng.choices(protocols, weights=w_values, k=1)[0]
                counts[chosen_proto] += 1
                src_port = self._rng.randint(49152, 65535)

                if chosen_proto == "HTTPS":
                    p_model = UnifiedTrafficEventModel(
                        simulationId=simulation_id, sourceDevice=source_dev, destinationDevice=dest_dev,
                        protocol=TransportProtocolEnum.TCP, sourcePort=src_port, destinationPort=443,
                        bytes=1200, packets=1, direction=TrafficDirectionEnum.OUTBOUND,
                        tcpState=SimulatedTcpStateEnum.ESTABLISHED, details={"app": "HTTPS"}
                    )
                elif chosen_proto == "HTTP":
                    p_model = UnifiedTrafficEventModel(
                        simulationId=simulation_id, sourceDevice=source_dev, destinationDevice=dest_dev,
                        protocol=TransportProtocolEnum.TCP, sourcePort=src_port, destinationPort=80,
                        bytes=650, packets=1, direction=TrafficDirectionEnum.OUTBOUND,
                        tcpState=SimulatedTcpStateEnum.ESTABLISHED, details={"app": "HTTP"}
                    )
                elif chosen_proto == "DNS":
                    p_model = UnifiedTrafficEventModel(
                        simulationId=simulation_id, sourceDevice=source_dev, destinationDevice=dest_dev,
                        protocol=TransportProtocolEnum.UDP, sourcePort=src_port, destinationPort=53,
                        bytes=128, packets=1, direction=TrafficDirectionEnum.OUTBOUND, details={"app": "DNS"}
                    )
                elif chosen_proto == "SSH":
                    p_model = UnifiedTrafficEventModel(
                        simulationId=simulation_id, sourceDevice=source_dev, destinationDevice=dest_dev,
                        protocol=TransportProtocolEnum.TCP, sourcePort=src_port, destinationPort=22,
                        bytes=850, packets=1, direction=TrafficDirectionEnum.OUTBOUND,
                        tcpState=SimulatedTcpStateEnum.ESTABLISHED, details={"app": "SSH"}
                    )
                else: # ICMP
                    p_model = UnifiedTrafficEventModel(
                        simulationId=simulation_id, sourceDevice=source_dev, destinationDevice=dest_dev,
                        protocol=TransportProtocolEnum.ICMP, sourcePort=None, destinationPort=None,
                        bytes=64, packets=1, direction=TrafficDirectionEnum.OUTBOUND,
                        icmpType=IcmpMessageTypeEnum.ECHO_REQUEST, details={"app": "ICMP"}
                    )
                packets.append(p_model)

        end_ts = datetime.now(timezone.utc).isoformat()
        percentages = {p: round((cnt / total_pkts) * 100, 2) for p, cnt in counts.items()}

        stats = WindowProtocolStats(
            windowPhase=phase,
            durationSeconds=duration_seconds,
            totalPackets=total_pkts,
            counts=counts,
            percentages=percentages,
            startTime=start_ts,
            endTime=end_ts
        )
        return stats, packets

    def runThreeStageScenario(
        self,
        source_dev: str = "client-01",
        dest_dev: str = "web-01",
        window_duration: int = 10,
        packets_per_second: int = 10,
        simulation_id: str = "sim-proto-01"
    ) -> ProtocolAnomalyRunResult:
        self._auto_provision(source_dev, dest_dev)

        # 1. Normal Window
        normal_stats, _ = self._simulate_window(
            phase=ProtocolWindowPhaseEnum.NORMAL_PERIOD,
            weights=self.NORMAL_PROFILE,
            duration_seconds=window_duration,
            packets_per_second=packets_per_second,
            source_dev=source_dev,
            dest_dev=dest_dev,
            simulation_id=simulation_id
        )

        # 2. Abnormal Skew Window (ICMP jumps to 65%)
        abnormal_stats, _ = self._simulate_window(
            phase=ProtocolWindowPhaseEnum.ABNORMAL_PERIOD,
            weights=self.ABNORMAL_PROFILE,
            duration_seconds=window_duration,
            packets_per_second=packets_per_second,
            source_dev=source_dev,
            dest_dev=dest_dev,
            simulation_id=simulation_id
        )

        # 3. Recovery Window (Back to Normal)
        recovery_stats, _ = self._simulate_window(
            phase=ProtocolWindowPhaseEnum.RECOVERY_PERIOD,
            weights=self.NORMAL_PROFILE,
            duration_seconds=window_duration,
            packets_per_second=packets_per_second,
            source_dev=source_dev,
            dest_dev=dest_dev,
            simulation_id=simulation_id
        )

        # Check for protocol anomaly in abnormal window
        detected_anomalies: List[ProtocolAnomalyEvent] = []
        if abnormal_stats.percentages.get("ICMP", 0) > 40.0:
            dev_ratio = round((abnormal_stats.percentages["ICMP"] - self.NORMAL_PROFILE["ICMP"] * 100) / 100.0, 2)
            anom = ProtocolAnomalyEvent(
                simulationId=simulation_id,
                timeWindow=ProtocolWindowPhaseEnum.ABNORMAL_PERIOD,
                sourceDevice=source_dev,
                destinationDevice=dest_dev,
                expectedDominantProtocol="HTTPS",
                observedDominantProtocol="ICMP",
                expectedPercentage=self.NORMAL_PROFILE["ICMP"] * 100,
                observedPercentage=abnormal_stats.percentages["ICMP"],
                deviation=dev_ratio,
                details={
                    "normalDistribution": self.NORMAL_PROFILE,
                    "observedDistribution": abnormal_stats.percentages
                }
            )
            detected_anomalies.append(anom)
            self._history_events.append(anom)

        total_duration = window_duration * 3
        total_events = normal_stats.totalPackets + abnormal_stats.totalPackets + recovery_stats.totalPackets

        return ProtocolAnomalyRunResult(
            totalDurationSeconds=total_duration,
            totalEvents=total_events,
            normalWindowStats=normal_stats,
            abnormalWindowStats=abnormal_stats,
            recoveryWindowStats=recovery_stats,
            detectedAnomalies=detected_anomalies
        )

    def getAnomalyEvents(self) -> List[ProtocolAnomalyEvent]:
        return list(self._history_events)

    def clear(self):
        self._history_events.clear()

protocol_anomaly_engine = ProtocolAnomalyEngine()