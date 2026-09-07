import math
from typing import Dict, Any, List
from scapy.all import IP, TCP, UDP, Raw

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

class NetworkFeatureWindow:
    """Transforms raw packet bursts or flow records into structured feature vectors."""

    @staticmethod
    def extract_window_features(packets: List[Any], duration_sec: float = 1.0) -> Dict[str, float]:
        duration = max(duration_sec, 0.001)
        total_packets = len(packets)
        total_bytes = sum(len(p) for p in packets)

        dst_ports = set()
        dst_ips = set()
        syn_count = 0
        ack_count = 0
        entropies = []

        for p in packets:
            if p.haslayer(IP):
                dst_ips.add(p[IP].dst)
                if p.haslayer(TCP):
                    dst_ports.add(p[TCP].dport)
                    flags = str(p[TCP].flags)
                    if "S" in flags and "A" not in flags:
                        syn_count += 1
                    if "A" in flags:
                        ack_count += 1
                elif p.haslayer(UDP):
                    dst_ports.add(p[UDP].dport)

            if p.haslayer(Raw):
                entropies.append(calculate_entropy(bytes(p[Raw].load)))

        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        syn_to_ack = (syn_count / ack_count) if ack_count > 0 else float(syn_count)

        return {
            "packet_rate": round(total_packets / duration, 2),
            "byte_rate": round((total_bytes * 8) / duration, 2),
            "unique_destinations": float(len(dst_ips)),
            "unique_ports": float(len(dst_ports)),
            "syn_to_ack_ratio": round(syn_to_ack, 2),
            "avg_payload_entropy": round(avg_entropy, 3)
        }