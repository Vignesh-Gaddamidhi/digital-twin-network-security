import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum,
    IcmpMessageTypeEnum, UnifiedTrafficEventModel
)
from services.digital_twin.simulation.generators.protocol_generators import protocol_coordinator

def run_protocol_generators_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 52: LOW-LEVEL PROTOCOL GENERATORS AUDIT (TCP, UDP, ICMP)")
    print("=" * 80 + "\n")

    protocol_coordinator.clear()

    # 1. Test TCP Traffic Flow & Lifecycle
    print("[1/4] Testing TCP State Lifecycle Generation (Client -> Web:443)...")
    tcp_events = protocol_coordinator.emitTcpFlow(
        src="client-01", dst="web-01", dst_port=443, payload_bytes=1200, simulation_id="sim-day52"
    )
    print(f"    Generated TCP Events: {len(tcp_events)}")
    states = [e.tcpState for e in tcp_events]
    print(f"    Observed TCP States : {[s.value for s in states]}")

    assert len(tcp_events) == 5 # SYN, ACK(Est), Data(Est), FIN, ACK(Closed)
    assert tcp_events[0].tcpState == SimulatedTcpStateEnum.CONNECTING
    assert tcp_events[1].tcpState == SimulatedTcpStateEnum.ESTABLISHED
    assert tcp_events[2].tcpState == SimulatedTcpStateEnum.ESTABLISHED
    assert tcp_events[2].bytes == 1200
    assert tcp_events[3].tcpState == SimulatedTcpStateEnum.CLOSING
    assert tcp_events[4].tcpState == SimulatedTcpStateEnum.CLOSED
    assert tcp_events[0].destinationPort == 443
    assert 49152 <= tcp_events[0].sourcePort <= 65535
    print("    [PASS] TCP state machine verified from 3-way handshake to teardown.")

    # 2. Test UDP Datagram Generation
    print("\n[2/4] Testing Connectionless UDP Datagram Generation (Client -> DNS:53)...")
    udp_evt = protocol_coordinator.emitUdpDatagram(
        src="client-01", dst="dns-01", dst_port=53, payload_bytes=128, simulation_id="sim-day52"
    )
    print(f"    UDP Event: {udp_evt.sourceDevice}:{udp_evt.sourcePort} -> {udp_evt.destinationDevice}:{udp_evt.destinationPort} ({udp_evt.protocol.value}) Size: {udp_evt.bytes}B")

    assert udp_evt.protocol == TransportProtocolEnum.UDP
    assert udp_evt.destinationPort == 53
    assert udp_evt.bytes == 128
    assert udp_evt.tcpState is None  # UDP has no TCP state
    print("    [PASS] UDP datagram generated with connectionless attributes.")

    # 3. Test ICMP Ping Pair Generation
    print("\n[3/4] Testing ICMP Echo Probe and Reciprocal Reply (Client <-> Web)...")
    req, rep = protocol_coordinator.emitIcmpPing(
        src="client-01", dst="web-01", simulation_id="sim-day52"
    )
    print(f"    ICMP Request : {req.sourceDevice} -> {req.destinationDevice} [{req.icmpType.value}] Seq: {req.details['icmp_seq']}")
    print(f"    ICMP Reply   : {rep.sourceDevice} -> {rep.destinationDevice} [{rep.icmpType.value}] Seq: {rep.details['icmp_seq']}")

    assert req.protocol == TransportProtocolEnum.ICMP
    assert rep.protocol == TransportProtocolEnum.ICMP
    assert req.icmpType == IcmpMessageTypeEnum.ECHO_REQUEST
    assert rep.icmpType == IcmpMessageTypeEnum.ECHO_REPLY
    assert req.direction == TrafficDirectionEnum.OUTBOUND
    assert rep.direction == TrafficDirectionEnum.INBOUND
    assert req.details["icmp_seq"] == rep.details["icmp_seq"]
    assert req.sourcePort is None and req.destinationPort is None
    print("    [PASS] ICMP Echo Request/Reply pairing verified.")

    # 4. Invariant & Boundary Condition Tests
    print("\n[4/4] Executing Protocol Boundary & Invariant Rejection Tests...")

    # Missing port on TCP
    try:
        UnifiedTrafficEventModel(
            sourceDevice="client-01", destinationDevice="web-01", protocol=TransportProtocolEnum.TCP,
            sourcePort=50000, destinationPort=None
        )
        assert False
    except ValueError:
        print("    [PASS] Rejected TCP event with missing destination port.")

    # Missing port on UDP
    try:
        UnifiedTrafficEventModel(
            sourceDevice="client-01", destinationDevice="dns-01", protocol=TransportProtocolEnum.UDP,
            sourcePort=50000, destinationPort=None
        )
        assert False
    except ValueError:
        print("    [PASS] Rejected UDP event with missing destination port.")

    # Out of range port (>65535)
    try:
        UnifiedTrafficEventModel(
            sourceDevice="client-01", destinationDevice="web-01", protocol=TransportProtocolEnum.TCP,
            sourcePort=50000, destinationPort=70000
        )
        assert False
    except ValidationError:
        print("    [PASS] Rejected out-of-range port (>65535).")

    # Negative byte count
    try:
        UnifiedTrafficEventModel(
            sourceDevice="client-01", destinationDevice="web-01", protocol=TransportProtocolEnum.TCP,
            sourcePort=50000, destinationPort=443, bytes=-10
        )
        assert False
    except ValidationError:
        print("    [PASS] Rejected negative byte count.")

    print("\n" + "=" * 80)
    print("       ALL DAY 52 PROTOCOL TRAFFIC GENERATOR TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_protocol_generators_suite()