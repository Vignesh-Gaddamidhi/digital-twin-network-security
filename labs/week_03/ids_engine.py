import sys
import math
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, Raw

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

class SignatureRule:
    def __init__(self, rule_id: int, name: str, protocol: str, dport: Optional[int] = None, 
                 payload_contains: Optional[bytes] = None, tcp_flags: Optional[str] = None, severity: str = "HIGH"):
        self.rule_id = rule_id
        self.name = name
        self.protocol = protocol
        self.dport = dport
        self.payload_contains = payload_contains
        self.tcp_flags = tcp_flags
        self.severity = severity

    def match(self, pkt_data: Dict[str, Any], raw_payload: bytes) -> bool:
        if self.protocol != "ANY" and pkt_data["protocol"] != self.protocol:
            return False
        if self.dport and pkt_data["destination_port"] != self.dport:
            return False
        if self.tcp_flags and pkt_data.get("tcp_flags") != self.tcp_flags:
            return False
        if self.payload_contains and self.payload_contains not in raw_payload:
            return False
        return True

class HybridIDSEngine:
    def __init__(self, pps_threshold: float = 40.0):
        self.pps_threshold = pps_threshold
        self.signatures: List[SignatureRule] = []
        self.alerts: List[Dict[str, Any]] = []
        self.source_history = defaultdict(list)
        self.load_default_signatures()

    def load_default_signatures(self):
        # Rule 1: TCP SYN Port Scan Probe
        self.signatures.append(SignatureRule(
            rule_id=200001,
            name="SCAN_RECON_PROBE",
            protocol="TCP",
            tcp_flags="S",
            dport=4444,
            severity="HIGH"
        ))
        # Rule 2: Shell Exploit Payload Injection
        self.signatures.append(SignatureRule(
            rule_id=200002,
            name="EXPLOIT_SHELL_COMMAND_ATTEMPT",
            protocol="TCP",
            payload_contains=b"/bin/sh",
            severity="CRITICAL"
        ))
        # Rule 3: Database Direct Unauthorized Access
        self.signatures.append(SignatureRule(
            rule_id=200003,
            name="UNAUTHORIZED_DB_INGRESS_PROBE",
            protocol="TCP",
            dport=5432,
            severity="HIGH"
        ))

    def process_packet(self, pkt: Any) -> Optional[Dict[str, Any]]:
        if not pkt.haslayer(IP):
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else None
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0
        tcp_flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else None
        
        raw_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        entropy = calculate_entropy(raw_payload)

        pkt_data = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": proto,
            "source_port": sport,
            "destination_port": dport,
            "tcp_flags": tcp_flags,
            "packet_length": len(pkt),
            "entropy": entropy
        }

        now = datetime.now(timezone.utc)
        self.source_history[src_ip].append(now.timestamp())
        # Keep only timestamps within the last 1.0 second
        self.source_history[src_ip] = [t for t in self.source_history[src_ip] if now.timestamp() - t <= 1.0]
        current_pps = len(self.source_history[src_ip])

        matched_alerts = []

        # 1. Signature-Based Inspection
        for sig in self.signatures:
            if sig.match(pkt_data, raw_payload):
                matched_alerts.append({
                    "engine": "SIGNATURE",
                    "rule_id": sig.rule_id,
                    "alert": sig.name,
                    "severity": sig.severity
                })

        # 2. Anomaly-Based Inspection
        if current_pps > self.pps_threshold:
            matched_alerts.append({
                "engine": "ANOMALY",
                "rule_id": 300001,
                "alert": f"RATE_SURGE_DETECTED ({current_pps} PPS)",
                "severity": "CRITICAL"
            })

        if entropy > 7.7 and dport not in (443, 8443):
            matched_alerts.append({
                "engine": "ANOMALY",
                "rule_id": 300002,
                "alert": f"HIGH_ENTROPY_SUSPICIOUS_PAYLOAD ({entropy})",
                "severity": "MEDIUM"
            })

        if matched_alerts:
            eve_event = {
                "timestamp": now.isoformat(),
                "event_type": "alert",
                "src_ip": src_ip,
                "src_port": sport,
                "dest_ip": dst_ip,
                "dest_port": dport,
                "proto": proto,
                "alerts": matched_alerts
            }
            self.alerts.append(eve_event)
            return eve_event

        return None