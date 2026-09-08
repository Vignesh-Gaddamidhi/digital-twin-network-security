import random
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.abnormal_traffic import (
    AnomalyTypeEnum, AnomalySeverityEnum, AnomalyProfile, AbnormalEventModel
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class AbnormalTrafficEngine:
    """Core framework generating measurable, parameter-driven network traffic anomalies."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random(54321)
        self._abnormal_events: List[AbnormalEventModel] = []
        self._raw_traffic_events: List[UnifiedTrafficEventModel] = []

    def _ensure_devices_exist(self, src: str, dst: str):
        if not device_registry.getDevice(src):
            raise DeviceNotFoundError(f"Source device '{src}' not found in Device Registry.")
        if not device_registry.getDevice(dst):
            raise DeviceNotFoundError(f"Target device '{dst}' not found in Device Registry.")

    def injectAnomaly(
        self,
        profile: AnomalyProfile,
        simulation_id: str = "sim-001"
    ) -> Tuple[AbnormalEventModel, List[UnifiedTrafficEventModel]]:
        self._ensure_devices_exist(profile.affectedDevice, profile.targetDevice)

        generated_packets: List[UnifiedTrafficEventModel] = []
        now_ts = datetime.now(timezone.utc).isoformat()

        # 1. TRAFFIC_SPIKE (Sudden volumetric rate escalation)
        if profile.anomalyType == AnomalyTypeEnum.TRAFFIC_SPIKE:
            base_rate_pkts = 10
            spike_pkts = int(base_rate_pkts * profile.intensity)
            dst_port = profile.targetPort or 443

            for _ in range(spike_pkts):
                src_port = self._rng.randint(49152, 65535)
                pkt = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=src_port,
                    destinationPort=dst_port,
                    bytes=self._rng.randint(1200, 1460),
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                    details={"anomaly": "VOLUMETRIC_SPIKE"}
                )
                generated_packets.append(pkt)

            abnormal_event = AbnormalEventModel(
                simulationId=simulation_id,
                deviceId=profile.affectedDevice,
                targetDevice=profile.targetDevice,
                anomalyType=AnomalyTypeEnum.TRAFFIC_SPIKE,
                severity=profile.severity,
                timestamp=now_ts,
                intensity=profile.intensity,
                protocol="TCP",
                destinationPort=dst_port,
                metricObserved="packets_per_tick",
                baselineValue=float(base_rate_pkts),
                abnormalValue=float(spike_pkts),
                details={"multiplier": profile.intensity, "totalPackets": spike_pkts}
            )

        # 2. CONNECTION_ANOMALY (Rapid TCP connection burst)
        elif profile.anomalyType == AnomalyTypeEnum.CONNECTION_ANOMALY:
            conn_count = int(5 * profile.intensity)
            dst_port = profile.targetPort or 80

            for _ in range(conn_count):
                src_port = self._rng.randint(49152, 65535)
                syn = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=src_port,
                    destinationPort=dst_port,
                    bytes=60,
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    tcpState=SimulatedTcpStateEnum.CONNECTING,
                    details={"flag": "SYN", "anomaly": "CONNECTION_BURST"}
                )
                generated_packets.append(syn)

            abnormal_event = AbnormalEventModel(
                simulationId=simulation_id,
                deviceId=profile.affectedDevice,
                targetDevice=profile.targetDevice,
                anomalyType=AnomalyTypeEnum.CONNECTION_ANOMALY,
                severity=profile.severity,
                timestamp=now_ts,
                intensity=profile.intensity,
                protocol="TCP",
                destinationPort=dst_port,
                metricObserved="concurrent_connections",
                baselineValue=5.0,
                abnormalValue=float(conn_count),
                details={"rapid_handshakes": conn_count}
            )

        # 3. PORT_ANOMALY (Scanning non-standard/unopened ports)
        elif profile.anomalyType == AnomalyTypeEnum.PORT_ANOMALY:
            probed_ports = [self._rng.randint(1025, 9999) for _ in range(int(8 * profile.intensity))]
            for p in probed_ports:
                src_port = self._rng.randint(49152, 65535)
                probe = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=src_port,
                    destinationPort=p,
                    bytes=60,
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    tcpState=SimulatedTcpStateEnum.CONNECTING,
                    details={"flag": "SYN", "anomaly": "PORT_SWEEP"}
                )
                generated_packets.append(probe)

            abnormal_event = AbnormalEventModel(
                simulationId=simulation_id,
                deviceId=profile.affectedDevice,
                targetDevice=profile.targetDevice,
                anomalyType=AnomalyTypeEnum.PORT_ANOMALY,
                severity=profile.severity,
                timestamp=now_ts,
                intensity=profile.intensity,
                protocol="TCP",
                destinationPort=probed_ports[0],
                metricObserved="unique_ports_contacted",
                baselineValue=1.0,
                abnormalValue=float(len(probed_ports)),
                details={"probed_port_count": len(probed_ports), "ports": probed_ports[:10]}
            )

        # 4. PROTOCOL_ANOMALY (Severe skew in expected protocol ratio)
        elif profile.anomalyType == AnomalyTypeEnum.PROTOCOL_ANOMALY:
            udp_storm_count = int(20 * profile.intensity)
            for _ in range(udp_storm_count):
                src_port = self._rng.randint(49152, 65535)
                dst_port = profile.targetPort or 53
                dgram = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.UDP,
                    sourcePort=src_port,
                    destinationPort=dst_port,
                    bytes=512,
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    details={"anomaly": "PROTOCOL_RATIO_SKEW"}
                )
                generated_packets.append(dgram)

            abnormal_event = AbnormalEventModel(
                simulationId=simulation_id,
                deviceId=profile.affectedDevice,
                targetDevice=profile.targetDevice,
                anomalyType=AnomalyTypeEnum.PROTOCOL_ANOMALY,
                severity=profile.severity,
                timestamp=now_ts,
                intensity=profile.intensity,
                protocol="UDP",
                destinationPort=53,
                metricObserved="udp_ratio_skew",
                baselineValue=19.2, # Week 8 baseline UDP %
                abnormalValue=85.0,
                details={"udp_packet_burst": udp_storm_count}
            )

        # 5. REPEATED_CONNECTION (Looped connection flapping / reconnect loops)
        else:
            loops_count = int(6 * profile.intensity)
            dst_port = profile.targetPort or 22
            fixed_src_port = 54000

            for _ in range(loops_count):
                syn = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.affectedDevice,
                    destinationDevice=profile.targetDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=fixed_src_port,
                    destinationPort=dst_port,
                    bytes=60,
                    packets=1,
                    direction=TrafficDirectionEnum.OUTBOUND,
                    tcpState=SimulatedTcpStateEnum.CONNECTING,
                    details={"anomaly": "REPEATED_RECONNECT_LOOP"}
                )
                rst = UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.targetDevice,
                    destinationDevice=profile.affectedDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=dst_port,
                    destinationPort=fixed_src_port,
                    bytes=54,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.FAILED,
                    details={"flag": "RST"}
                )
                generated_packets.extend([syn, rst])

            abnormal_event = AbnormalEventModel(
                simulationId=simulation_id,
                deviceId=profile.affectedDevice,
                targetDevice=profile.targetDevice,
                anomalyType=AnomalyTypeEnum.REPEATED_CONNECTION,
                severity=profile.severity,
                timestamp=now_ts,
                intensity=profile.intensity,
                protocol="TCP",
                destinationPort=dst_port,
                metricObserved="reconnection_frequency",
                baselineValue=0.1,
                abnormalValue=float(loops_count),
                details={"reconnect_flaps": loops_count}
            )

        self._abnormal_events.append(abnormal_event)
        self._raw_traffic_events.extend(generated_packets)
        return abnormal_event, generated_packets

    def getAbnormalEvents(self) -> List[AbnormalEventModel]:
        return list(self._abnormal_events)

    def getRawTrafficEvents(self) -> List[UnifiedTrafficEventModel]:
        return list(self._raw_traffic_events)

    def clear(self):
        self._abnormal_events.clear()
        self._raw_traffic_events.clear()

abnormal_traffic_engine = AbnormalTrafficEngine()