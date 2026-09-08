import random
from typing import List, Tuple, Optional
from datetime import datetime, timezone

from packages.shared_types.src.repeated_connection import (
    RepeatedConnectionProfile, RepeatedConnectionEvent
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry

class RepeatedConnectionEngine:
    """Generates rapid, repeated connection attempts (e.g. 100 attempts in 10s: 3 succ, 97 fail)."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random(331199)
        self._history: List[RepeatedConnectionEvent] = []

    def _auto_provision(self, src: str, dst: str, port: int):
        from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
        if not device_registry.getDevice(src):
            device_registry.createDevice(NetworkDeviceModel(id=src, hostname=src.upper(), type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL))
        if not device_registry.getDevice(dst):
            device_registry.createDevice(NetworkDeviceModel(id=dst, hostname=dst.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[port]))

    def runScenario(
        self,
        profile: RepeatedConnectionProfile,
        simulation_id: str = "sim-rep-01"
    ) -> Tuple[RepeatedConnectionEvent, List[UnifiedTrafficEventModel]]:
        self._auto_provision(profile.sourceDevice, profile.destinationDevice, profile.destinationPort)

        succ_target = max(1, int(round(profile.attemptCount * profile.expectedSuccessRate)))
        fail_target = profile.attemptCount - succ_target

        packets: List[UnifiedTrafficEventModel] = []
        now_ts = datetime.now(timezone.utc).isoformat()

        # Generate the rapid sequence
        for i in range(profile.attemptCount):
            src_port = self._rng.randint(49152, 65535)
            is_succ = (i < succ_target)

            # SYN attempt
            packets.append(UnifiedTrafficEventModel(
                simulationId=simulation_id,
                sourceDevice=profile.sourceDevice,
                destinationDevice=profile.destinationDevice,
                protocol=TransportProtocolEnum.TCP,
                sourcePort=src_port,
                destinationPort=profile.destinationPort,
                bytes=60,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=SimulatedTcpStateEnum.CONNECTING,
                details={"attemptIndex": i + 1}
            ))

            if is_succ:
                packets.append(UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.destinationDevice,
                    destinationDevice=profile.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=profile.destinationPort,
                    destinationPort=src_port,
                    bytes=54,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.ESTABLISHED,
                    details={"attemptIndex": i + 1, "flag": "ACK"}
                ))
            else:
                packets.append(UnifiedTrafficEventModel(
                    simulationId=simulation_id,
                    sourceDevice=profile.destinationDevice,
                    destinationDevice=profile.sourceDevice,
                    protocol=TransportProtocolEnum.TCP,
                    sourcePort=profile.destinationPort,
                    destinationPort=src_port,
                    bytes=54,
                    packets=1,
                    direction=TrafficDirectionEnum.INBOUND,
                    tcpState=SimulatedTcpStateEnum.FAILED,
                    details={"attemptIndex": i + 1, "flag": "RST"}
                ))

        event = RepeatedConnectionEvent(
            simulationId=simulation_id,
            sourceDevice=profile.sourceDevice,
            destinationDevice=profile.destinationDevice,
            destinationPort=profile.destinationPort,
            attemptCount=profile.attemptCount,
            successfulCount=succ_target,
            failedCount=fail_target,
            windowSeconds=profile.windowSeconds,
            timestamp=now_ts,
            details={"packetCount": len(packets)}
        )

        self._history.append(event)
        return event, packets

    def getEvents(self) -> List[RepeatedConnectionEvent]:
        return list(self._history)

    def clear(self):
        self._history.clear()

repeated_connection_engine = RepeatedConnectionEngine()