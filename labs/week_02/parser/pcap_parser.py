import sys
import math
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, DNS, Raw

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of payload byte distribution (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

def detect_application_protocol(packet: Any) -> str:
    """Detects L7 application protocol via ports and byte signatures."""
    if packet.haslayer(DNS):
        return "DNS"

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if 53 in (sport, dport):
            return "DNS"
        if 80 in (sport, dport) or 8080 in (sport, dport):
            return "HTTP"
        if 443 in (sport, dport):
            return "TLS"

    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        if 53 in (sport, dport):
            return "DNS"

    if packet.haslayer(Raw):
        load = packet[Raw].load
        # Check HTTP methods
        if any(load.startswith(verb) for verb in [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HTTP/"]):
            return "HTTP"
        # Check TLS Handshake Record (0x16) and TLS Version (0x0301, 0x0302, 0x0303)
        if len(load) >= 3 and load[0] == 0x16 and load[1] == 0x03 and load[2] in (0x01, 0x02, 0x03):
            return "TLS"

    return "UNKNOWN"

class PcapParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def parse_to_json(self, output_json_path: Optional[str] = None) -> List[Dict[str, Any]]:
        print(f"[*] Reading and parsing PCAP: {self.pcap_path}")
        packets = rdpcap(self.pcap_path)
        events: List[Dict[str, Any]] = []

        for idx, pkt in enumerate(packets, start=1):
            pkt_time = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
            
            event: Dict[str, Any] = {
                "packet_index": idx,
                "timestamp": pkt_time,
                "source_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                "destination_mac": pkt[Ether].dst if pkt.haslayer(Ether) else None,
                "source_ip": pkt[IP].src if pkt.haslayer(IP) else None,
                "destination_ip": pkt[IP].dst if pkt.haslayer(IP) else None,
                "ip_ttl": pkt[IP].ttl if pkt.haslayer(IP) else None,
                "protocol": "OTHER",
                "detected_application": detect_application_protocol(pkt),
                "source_port": None,
                "destination_port": None,
                "tcp_flags": None,
                "packet_length": len(pkt),
                "payload_entropy": 0.0,
                "payload_preview": None
            }

            if pkt.haslayer(TCP):
                event["protocol"] = "TCP"
                event["source_port"] = pkt[TCP].sport
                event["destination_port"] = pkt[TCP].dport
                event["tcp_flags"] = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                event["protocol"] = "UDP"
                event["source_port"] = pkt[UDP].sport
                event["destination_port"] = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                event["protocol"] = "ICMP"
                event["destination_port"] = 0

            if pkt.haslayer(Raw):
                raw_bytes = pkt[Raw].load
                event["payload_entropy"] = calculate_entropy(raw_bytes)
                event["payload_preview"] = raw_bytes[:40].decode("utf-8", errors="replace").replace("\r\n", " ")

            events.append(event)

        print(f"[+] Successfully extracted {len(events)} structured security events.")
        
        if output_json_path:
            with open(output_json_path, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2)
            print(f"[+] Output written to: {output_json_path}")

        return events

if __name__ == "__main__":
    parser = PcapParser("labs/week_02/pcap/lab_sample.pcap")
    parser.parse_to_json("labs/week_02/parser/parsed_packets.json")