import random
from typing import List, Tuple, Optional
from datetime import datetime, timezone, timedelta

from packages.shared_types.src.traffic_pattern import (
    GenericTrafficPatternModel, PatternTypeEnum, ConnectionBehaviourEnum,
    PatternGenerationResult
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum,
    IcmpMessageTypeEnum, UnifiedTrafficEventModel
)
from services.digital_twin.simulation.attack.generators.timing_engine import timing_engine

class PatternGeneratorEngine:
    """Generates synthetic, parameter-driven packet event streams from GenericTrafficPatternModel."""

    @staticmethod
    def validate_pattern(pattern: GenericTrafficPatternModel):
        if not pattern.destinationPorts:
            raise ValueError("Traffic pattern must define at least one destination port.")
        if pattern.timing.durationSeconds <= 0:
            raise ValueError("Timing duration must be strictly positive.")
        if pattern.timing.rateEventsPerSecond <= 0:
            raise ValueError("Timing rate must be strictly positive.")

    def generate_events(
        self,
        pattern: GenericTrafficPatternModel,
        simulation_id: str = "sim-pat-01",
        base_timestamp: Optional[datetime] = None
    ) -> Tuple[PatternGenerationResult, List[UnifiedTrafficEventModel]]:
        self.validate_pattern(pattern)
        rng = random.Random(pattern.seed)
        start_dt = base_timestamp if base_timestamp is not None else datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        # 1. Compute timing offsets
        timeline = timing_engine.generate_timeline(pattern.timing, pattern.patternType, rng)

        events: List[UnifiedTrafficEventModel] = []
        ports = pattern.destinationPorts
        port_count = len(ports)
        proto_enum = TransportProtocolEnum(pattern.protocol.upper())

        total_bytes = 0

        # 2. Iterate through timeline
        for idx, offset_sec in enumerate(timeline):
            event_dt = start_dt + timedelta(seconds=offset_sec)
            iso_ts = event_dt.isoformat()

            # Determine destination port based on pattern strategy
            if pattern.patternType == PatternTypeEnum.SEQUENTIAL:
                dst_port = ports[idx % port_count]
            elif pattern.patternType == PatternTypeEnum.RANDOMIZED:
                dst_port = rng.choice(ports)
            else:
                dst_port = ports[idx % port_count]

            # Source port
            if pattern.sourcePortStrategy == "FIXED" and pattern.fixedSourcePort:
                src_port = pattern.fixedSourcePort
            else:
                src_port = rng.randint(49152, 65535)

            # Modulate TCP State according to ConnectionBehaviour
            tcp_state = None
            icmp_type = None
            flags = {}

            if proto_enum == TransportProtocolEnum.TCP:
                if pattern.connectionBehaviour == ConnectionBehaviourEnum.RESET_IMMEDIATE:
                    tcp_state = SimulatedTcpStateEnum.CONNECTING
                    flags = {"flag": "SYN", "action": "EXPECT_RST"}
                elif pattern.connectionBehaviour == ConnectionBehaviourEnum.HALF_OPEN:
                    tcp_state = SimulatedTcpStateEnum.CONNECTING
                    flags = {"flag": "SYN", "action": "DROP_ACK"}
                elif pattern.connectionBehaviour == ConnectionBehaviourEnum.FULL_HANDSHAKE:
                    tcp_state = SimulatedTcpStateEnum.ESTABLISHED
                    flags = {"flag": "ACK"}
                else:
                    tcp_state = SimulatedTcpStateEnum.ESTABLISHED
            elif proto_enum == TransportProtocolEnum.ICMP:
                icmp_type = IcmpMessageTypeEnum.ECHO_REQUEST
                src_port = None
                dst_port = None

            pkt = UnifiedTrafficEventModel(
                simulationId=simulation_id,
                sourceDevice=pattern.sourceDevice,
                destinationDevice=pattern.targetDevice,
                protocol=proto_enum,
                sourcePort=src_port,
                destinationPort=dst_port,
                bytes=pattern.packetSizeBytes,
                packets=1,
                direction=TrafficDirectionEnum.OUTBOUND,
                tcpState=tcp_state,
                icmpType=icmp_type,
                timestamp=iso_ts,
                details={
                    "patternId": pattern.patternId,
                    "patternType": pattern.patternType.value,
                    **flags,
                    **pattern.parameters
                }
            )
            events.append(pkt)
            total_bytes += pattern.packetSizeBytes

        first_ts = events[0].timestamp if events else None
        last_ts = events[-1].timestamp if events else None

        result = PatternGenerationResult(
            patternId=pattern.patternId,
            patternType=pattern.patternType,
            protocol=pattern.protocol,
            totalPacketsEmitted=len(events),
            totalBytesTransferred=total_bytes,
            durationSecondsObserved=pattern.timing.durationSeconds,
            portsTargeted=sorted(list(set(p for p in ports))),
            firstTimestamp=first_ts,
            lastTimestamp=last_ts
        )

        return result, events

pattern_generator_engine = PatternGeneratorEngine()