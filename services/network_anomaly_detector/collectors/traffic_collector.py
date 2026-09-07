from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict
from scapy.all import IP, TCP, UDP

class FlowRecord:
    def __init__(self, src_ip: str, dst_ip: str, proto: str, sport: Optional[int], dport: Optional[int]):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = datetime.now(timezone.utc).timestamp()
        self.last_time = self.start_time

    def update(self, pkt_len: int, timestamp: float):
        self.packet_count += 1
        self.byte_count += pkt_len
        self.last_time = timestamp

    @property
    def duration(self) -> float:
        return max(0.001, self.last_time - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.src_ip,
            "destination_ip": self.dst_ip,
            "protocol": self.proto,
            "source_port": self.sport,
            "destination_port": self.dport,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 3)
        }

class TrafficCollector:
    """Collects and aggregates raw packets into windowed flow summaries."""

    def __init__(self):
        self.active_flows: Dict[tuple, FlowRecord] = {}

    def ingest_packet(self, pkt: Any, timestamp: Optional[float] = None) -> Optional[Dict[str, Any]]:
        if not pkt.haslayer(IP):
            return None

        ts = timestamp or datetime.now(timezone.utc).timestamp()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else None
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else None

        flow_key = (src_ip, dst_ip, proto, dport)
        if flow_key not in self.active_flows:
            self.active_flows[flow_key] = FlowRecord(src_ip, dst_ip, proto, sport, dport)

        self.active_flows[flow_key].update(len(pkt), ts)
        return self.active_flows[flow_key].to_dict()

    def flush_window(self) -> List[Dict[str, Any]]:
        summaries = [f.to_dict() for f in self.active_flows.values()]
        self.active_flows.clear()
        return summaries