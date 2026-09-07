import time
import random
from typing import Dict, Any

class SyntheticTrafficGenerator:
    """Generates multi-layer network flow telemetry across L3, L4, and L7."""

    @staticmethod
    def generate_flow_telemetry(scenario: str = "BENIGN") -> Dict[str, Any]:
        timestamp = time.time()
        
        if scenario == "BENIGN":
            flow_type = random.choice(["HTTP", "HTTPS", "DNS"])
            
            if flow_type == "DNS":
                return {
                    "timestamp": timestamp,
                    "layer": "L7_DNS",
                    "src_ip": f"192.168.1.{random.randint(10, 50)}",
                    "dst_ip": "192.168.1.1", # Gateway DNS Resolver
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 53,
                    "protocol": "UDP",
                    "dns_query": random.choice(["api.internal.network", "srv-db-01.internal", "updates.os.org"]),
                    "query_type": "A",
                    "byte_entropy": round(random.uniform(2.1, 3.5), 3),
                    "label": "NORMAL_DNS"
                }
            elif flow_type == "HTTPS":
                return {
                    "timestamp": timestamp,
                    "layer": "L7_HTTPS",
                    "src_ip": f"192.168.1.{random.randint(10, 50)}",
                    "dst_ip": "192.168.1.10",
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "sni": "api.internal.network",
                    "tls_version": "TLSv1.3",
                    "byte_entropy": round(random.uniform(7.6, 7.98), 3), # High cryptographic entropy
                    "flow_duration_ms": round(random.uniform(20.0, 150.0), 2),
                    "label": "NORMAL_HTTPS"
                }
            else: # HTTP
                return {
                    "timestamp": timestamp,
                    "layer": "L7_HTTP",
                    "src_ip": f"192.168.1.{random.randint(10, 50)}",
                    "dst_ip": "192.168.1.10",
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 80,
                    "protocol": "TCP",
                    "http_method": "GET",
                    "http_path": random.choice(["/health", "/api/v1/status", "/index.html"]),
                    "http_status": 200,
                    "byte_entropy": round(random.uniform(3.0, 4.5), 3),
                    "flow_duration_ms": round(random.uniform(5.0, 50.0), 2),
                    "label": "NORMAL_HTTP"
                }
            
        elif scenario == "PORT_SCAN":
            return {
                "timestamp": timestamp,
                "layer": "L4_TRANSPORT",
                "src_ip": "10.0.0.99",
                "dst_ip": "192.168.1.10",
                "src_port": random.randint(40000, 60000),
                "dst_port": random.randint(1, 1024),
                "protocol": "TCP",
                "flow_duration_ms": round(random.uniform(0.1, 2.0), 2),
                "packet_rate": round(random.uniform(250.0, 900.0), 1),
                "byte_entropy": round(random.uniform(0.5, 1.8), 3),
                "syn_ack_ratio": 0.05,
                "label": "RECON_SCAN"
            }
            
        elif scenario == "EXFILTRATION":
            return {
                "timestamp": timestamp,
                "layer": "L7_EXFILTRATION",
                "src_ip": "192.168.1.20",
                "dst_ip": "198.51.100.4",
                "src_port": random.randint(49152, 65535),
                "dst_port": 443,
                "protocol": "TCP",
                "flow_duration_ms": round(random.uniform(5000.0, 30000.0), 2),
                "packet_rate": round(random.uniform(800.0, 2000.0), 1),
                "byte_entropy": round(random.uniform(7.9, 7.999), 3),
                "syn_ack_ratio": 0.98,
                "label": "DATA_EXFIL"
            }
            
        raise ValueError(f"Unknown traffic generation scenario: {scenario}")