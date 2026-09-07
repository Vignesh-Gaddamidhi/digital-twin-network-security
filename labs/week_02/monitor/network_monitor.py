import sys
import time
from datetime import datetime, timezone
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw

class ConnectionRecord:
    def __init__(self, src_ip: str, dst_ip: str, proto: str, port: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.port = port
        self.state = "ACTIVE"
        self.packet_count = 0
        self.byte_count = 0
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def update(self, packet_bytes: int, flags: Optional[str] = None):
        self.packet_count += 1
        self.byte_count += packet_bytes
        self.last_seen = datetime.now(timezone.utc).isoformat()
        if flags and "F" in flags:
            self.state = "CLOSED"
        elif flags and "R" in flags:
            self.state = "RESET"

class AnomalyEngine:
    """Evaluates rule-based behavioral indicators."""

    @staticmethod
    def inspect(pkt_telemetry: Dict[str, Any], conn_rate: float) -> Dict[str, str]:
        proto = pkt_telemetry["protocol"]
        dport = pkt_telemetry["destination_port"]
        bytes_len = pkt_telemetry["packet_length"]
        src = pkt_telemetry["source_ip"]

        # 1. Critical Rule: Traffic Volume Burst (> 50 PPS rate)
        if conn_rate > 50.0:
            return {"level": "CRITICAL", "reason": f"High traffic burst detected from {src} ({conn_rate:.1f} PPS)"}

        # 2. Critical Rule: Suspicious Recon Port Scan Activity
        if proto == "TCP" and dport in (23, 445, 3389, 4444):
            return {"level": "CRITICAL", "reason": f"Connection attempt to high-risk port {dport} by {src}"}

        # 3. Warning Rule: Unexpected UDP Ports
        if proto == "UDP" and dport not in (53, 67, 68, 6000):
            return {"level": "WARNING", "reason": f"Unexpected UDP service port {dport} accessed by {src}"}

        # 4. Warning Rule: Large Payload on non-standard port
        if bytes_len > 1400 and dport not in (80, 443):
            return {"level": "WARNING", "reason": f"Large packet ({bytes_len} bytes) targeting non-web port {dport}"}

        # 5. Normal Baseline
        return {"level": "INFO", "reason": "Traffic matches standard enterprise baseline profile"}

class NetworkMonitorEngine:
    def __init__(self):
        self.connections: Dict[tuple, ConnectionRecord] = {}
        self.protocol_counts: Counter = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self.source_counts: Counter = Counter()
        self.start_time = time.time()
        self.anomaly_engine = AnomalyEngine()
        self.alerts: List[Dict[str, Any]] = []

    def process_packet(self, pkt: Any) -> Optional[Dict[str, Any]]:
        if not pkt.haslayer(IP):
            return None

        self.total_packets += 1
        pkt_len = len(pkt)
        self.total_bytes += pkt_len

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        self.source_counts[src_ip] += 1

        proto = "OTHER"
        sport = None
        dport = 0
        tcp_flags = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            dport = 0

        self.protocol_counts[proto] += 1

        # Track Connection State
        conn_key = (src_ip, dst_ip, proto, dport)
        if conn_key not in self.connections:
            self.connections[conn_key] = ConnectionRecord(src_ip, dst_ip, proto, dport)
        self.connections[conn_key].update(pkt_len, tcp_flags)

        elapsed = max(time.time() - self.start_time, 0.001)
        pps = self.total_packets / elapsed

        pkt_telemetry = {
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": proto,
            "source_port": sport,
            "destination_port": dport,
            "packet_length": pkt_len,
            "tcp_flags": tcp_flags
        }

        # Evaluate Indicators
        indicator = self.anomaly_engine.inspect(pkt_telemetry, conn_rate=pps)
        if indicator["level"] in ("WARNING", "CRITICAL"):
            alert_entry = {**pkt_telemetry, **indicator}
            self.alerts.append(alert_entry)

        return {**pkt_telemetry, "alert": indicator}

    def render_dashboard(self) -> Dict[str, Any]:
        elapsed = max(time.time() - self.start_time, 0.001)
        pps = self.total_packets / elapsed
        bps = (self.total_bytes * 8) / elapsed

        proto_stats = {
            proto: round((count / self.total_packets) * 100, 1)
            for proto, count in self.protocol_counts.items()
        } if self.total_packets > 0 else {}

        active_table = [
            {
                "source": c.src_ip,
                "destination": c.dst_ip,
                "protocol": c.proto,
                "port": c.port,
                "packets": c.packet_count,
                "bytes": c.byte_count,
                "state": c.state
            }
            for c in self.connections.values()
        ]

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_sec": round(pps, 2),
            "bits_per_sec": round(bps, 2),
            "protocol_distribution": proto_stats,
            "active_connections": active_table,
            "alerts_count": len(self.alerts)
        }