import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw

class PacketCraftingLab:
    """Demonstrates deterministic multi-layer packet composition and telemetry extraction."""

    @staticmethod
    def craft_tcp_syn_packet() -> Ether:
        return (
            Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") /
            IP(src="192.168.1.11", dst="192.168.1.10", ttl=64, id=1001) /
            TCP(sport=50000, dport=5000, flags="S", seq=1000, window=65535) /
            Raw(load=b"SYN_PROBE_INITIALIZE")
        )

    @staticmethod
    def craft_udp_telemetry_packet() -> Ether:
        return (
            Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:00") /
            IP(src="192.168.1.11", dst="192.168.1.1", ttl=64) /
            UDP(sport=54112, dport=53) /
            Raw(load=b"DNS_QUERY_PAYLOAD_INTERNAL")
        )

    @staticmethod
    def craft_icmp_echo_packet() -> Ether:
        return (
            Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") /
            IP(src="192.168.1.11", dst="192.168.1.10", ttl=64) /
            ICMP(type=8, code=0, id=0x1234, seq=1) /
            Raw(load=b"PING_PROBE_REACHABILITY")
        )

    @staticmethod
    def extract_telemetry_for_digital_twin(pkt: Any, packet_idx: int) -> Dict[str, Any]:
        """Parses a Scapy packet into a normalized Digital Twin Connection Record."""
        telemetry: Dict[str, Any] = {
            "packet_id": packet_idx,
            "timestamp": datetime.utcnow().isoformat(),
            "source_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
            "destination_mac": pkt[Ether].dst if pkt.haslayer(Ether) else None,
            "source_ip": pkt[IP].src if pkt.haslayer(IP) else None,
            "destination_ip": pkt[IP].dst if pkt.haslayer(IP) else None,
            "protocol": "UNKNOWN",
            "source_port": None,
            "destination_port": None,
            "tcp_flags": None,
            "packet_bytes": len(pkt),
            "payload_preview": None
        }

        if pkt.haslayer(TCP):
            telemetry["protocol"] = "TCP"
            telemetry["source_port"] = pkt[TCP].sport
            telemetry["destination_port"] = pkt[TCP].dport
            telemetry["tcp_flags"] = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            telemetry["protocol"] = "UDP"
            telemetry["source_port"] = pkt[UDP].sport
            telemetry["destination_port"] = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            telemetry["protocol"] = "ICMP"
            telemetry["destination_port"] = 0

        if pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            telemetry["payload_preview"] = raw_data[:32].decode("utf-8", errors="replace")

        return telemetry

def run_lab():
    print("================================================================================")
    print("           WEEK 2 - DAY 10: SCAPY PACKET CRAFTING & PARSING LAB                 ")
    print("================================================================================\n")

    lab = PacketCraftingLab()
    packets = [
        lab.craft_tcp_syn_packet(),
        lab.craft_udp_telemetry_packet(),
        lab.craft_icmp_echo_packet()
    ]

    for idx, pkt in enumerate(packets, start=1):
        telemetry = lab.extract_telemetry_for_digital_twin(pkt, idx)
        print(f"Packet #{telemetry['packet_id']}")
        print(f"  Source      : {telemetry['source_ip']} ({telemetry['source_mac']})")
        print(f"  Destination : {telemetry['destination_ip']} ({telemetry['destination_mac']})")
        print(f"  Protocol    : {telemetry['protocol']}")
        print(f"  Src Port    : {telemetry['source_port']}")
        print(f"  Dst Port    : {telemetry['destination_port']}")
        if telemetry['tcp_flags']:
            print(f"  TCP Flags   : {telemetry['tcp_flags']}")
        print(f"  Size        : {telemetry['packet_bytes']} bytes")
        print(f"  Payload     : {telemetry['payload_preview']}")
        print("-" * 50)

    print("[+] Scapy packet crafting and telemetry parsing verified successfully.")

if __name__ == "__main__":
    run_lab()