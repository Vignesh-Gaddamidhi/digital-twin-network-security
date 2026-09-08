import random
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum,
    IcmpMessageTypeEnum, UnifiedTrafficEventModel
)

class TcpTrafficGenerator:
    """Generates synthetic TCP traffic with realistic state-machine transitions."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()
        # session_key -> current state
        self._active_sessions: Dict[str, SimulatedTcpStateEnum] = {}

    def _make_key(self, src: str, dst: str, src_port: int, dst_port: int) -> str:
        return f"{src}:{src_port}->{dst}:{dst_port}"

    def generateHandshake(
        self, source_dev: str, dest_dev: str, dest_port: int = 443,
        source_port: Optional[int] = None, simulation_id: str = "sim-001"
    ) -> List[UnifiedTrafficEventModel]:
        src_port = source_port or self._rng.randint(49152, 65535)
        key = self._make_key(source_dev, dest_dev, src_port, dest_port)

        # SYN (NEW / CONNECTING)
        syn_evt = UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=TransportProtocolEnum.TCP,
            sourcePort=src_port,
            destinationPort=dest_port,
            bytes=60, # SYN frame size
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            tcpState=SimulatedTcpStateEnum.CONNECTING,
            details={"flag": "SYN"}
        )

        # SYN-ACK + ACK (ESTABLISHED)
        est_evt = UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=TransportProtocolEnum.TCP,
            sourcePort=src_port,
            destinationPort=dest_port,
            bytes=54,
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            tcpState=SimulatedTcpStateEnum.ESTABLISHED,
            details={"flag": "ACK"}
        )
        self._active_sessions[key] = SimulatedTcpStateEnum.ESTABLISHED
        return [syn_evt, est_evt]

    def generateDataTransmission(
        self, source_dev: str, dest_dev: str, dest_port: int = 443,
        source_port: Optional[int] = None, payload_bytes: Optional[int] = None,
        simulation_id: str = "sim-001"
    ) -> UnifiedTrafficEventModel:
        src_port = source_port or self._rng.randint(49152, 65535)
        bytes_count = payload_bytes or self._rng.randint(256, 1460)
        return UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=TransportProtocolEnum.TCP,
            sourcePort=src_port,
            destinationPort=dest_port,
            bytes=bytes_count,
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            tcpState=SimulatedTcpStateEnum.ESTABLISHED,
            details={"type": "DATA_TRANSMISSION"}
        )

    def generateTeardown(
        self, source_dev: str, dest_dev: str, dest_port: int,
        source_port: int, simulation_id: str = "sim-001"
    ) -> List[UnifiedTrafficEventModel]:
        key = self._make_key(source_dev, dest_dev, source_port, dest_port)
        fin_evt = UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=TransportProtocolEnum.TCP,
            sourcePort=source_port,
            destinationPort=dest_port,
            bytes=60,
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            tcpState=SimulatedTcpStateEnum.CLOSING,
            details={"flag": "FIN"}
        )
        closed_evt = UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=dest_dev,
            destinationDevice=source_dev,
            protocol=TransportProtocolEnum.TCP,
            sourcePort=dest_port,
            destinationPort=source_port,
            bytes=54,
            packets=1,
            direction=TrafficDirectionEnum.INBOUND,
            tcpState=SimulatedTcpStateEnum.CLOSED,
            details={"flag": "ACK"}
        )
        self._active_sessions[key] = SimulatedTcpStateEnum.CLOSED
        return [fin_evt, closed_evt]


class UdpTrafficGenerator:
    """Generates connectionless UDP datagram traffic."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()

    def generateDatagram(
        self, source_dev: str, dest_dev: str, dest_port: int = 53,
        source_port: Optional[int] = None, payload_bytes: Optional[int] = None,
        simulation_id: str = "sim-001"
    ) -> UnifiedTrafficEventModel:
        src_port = source_port or self._rng.randint(49152, 65535)
        bytes_count = payload_bytes or (self._rng.randint(64, 512) if dest_port == 53 else self._rng.randint(128, 1400))
        return UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=TransportProtocolEnum.UDP,
            sourcePort=src_port,
            destinationPort=dest_port,
            bytes=bytes_count,
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            details={"type": "DATAGRAM"}
        )


class IcmpTrafficGenerator:
    """Generates ICMP Echo Request and Echo Reply diagnostic traffic."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()

    def generatePingPair(
        self, source_dev: str, dest_dev: str, ttl: int = 64,
        payload_bytes: int = 64, simulation_id: str = "sim-001"
    ) -> Tuple[UnifiedTrafficEventModel, UnifiedTrafficEventModel]:
        seq_id = self._rng.randint(1, 65535)
        
        request = UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=TransportProtocolEnum.ICMP,
            sourcePort=None,
            destinationPort=None,
            bytes=payload_bytes,
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            icmpType=IcmpMessageTypeEnum.ECHO_REQUEST,
            details={"icmp_seq": seq_id, "ttl": ttl}
        )

        reply = UnifiedTrafficEventModel(
            simulationId=simulation_id,
            sourceDevice=dest_dev,
            destinationDevice=source_dev,
            protocol=TransportProtocolEnum.ICMP,
            sourcePort=None,
            destinationPort=None,
            bytes=payload_bytes,
            packets=1,
            direction=TrafficDirectionEnum.INBOUND,
            icmpType=IcmpMessageTypeEnum.ECHO_REPLY,
            details={"icmp_seq": seq_id, "ttl": ttl - 1}
        )
        return request, reply


class ProtocolSimulationCoordinator:
    """Unifies and coordinates TCP, UDP, and ICMP protocol generation."""

    def __init__(self, seed: int = 12345):
        self._rng = random.Random(seed)
        self.tcp = TcpTrafficGenerator(self._rng)
        self.udp = UdpTrafficGenerator(self._rng)
        self.icmp = IcmpTrafficGenerator(self._rng)
        self._generated_events: List[UnifiedTrafficEventModel] = []

    def emitTcpFlow(self, src: str, dst: str, dst_port: int = 443, payload_bytes: int = 1200, simulation_id: str = "sim-001") -> List[UnifiedTrafficEventModel]:
        src_port = self._rng.randint(49152, 65535)
        events = []
        # Handshake
        events.extend(self.tcp.generateHandshake(src, dst, dst_port, src_port, simulation_id=simulation_id))
        # Transmission
        events.append(self.tcp.generateDataTransmission(src, dst, dst_port, src_port, payload_bytes=payload_bytes, simulation_id=simulation_id))
        # Teardown
        events.extend(self.tcp.generateTeardown(src, dst, dst_port, src_port, simulation_id=simulation_id))
        self._generated_events.extend(events)
        return events

    def emitUdpDatagram(self, src: str, dst: str, dst_port: int = 53, payload_bytes: int = 128, simulation_id: str = "sim-001") -> UnifiedTrafficEventModel:
        evt = self.udp.generateDatagram(src, dst, dest_port=dst_port, payload_bytes=payload_bytes, simulation_id=simulation_id)
        self._generated_events.append(evt)
        return evt

    def emitIcmpPing(self, src: str, dst: str, simulation_id: str = "sim-001") -> Tuple[UnifiedTrafficEventModel, UnifiedTrafficEventModel]:
        req, rep = self.icmp.generatePingPair(src, dst, simulation_id=simulation_id)
        self._generated_events.extend([req, rep])
        return req, rep

    def getEvents(self) -> List[UnifiedTrafficEventModel]:
        return list(self._generated_events)

    def clear(self):
        self._generated_events.clear()

protocol_coordinator = ProtocolSimulationCoordinator()