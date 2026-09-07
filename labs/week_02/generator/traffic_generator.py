import sys
import json
import time
import random
from pathlib import Path
from typing import List, Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import wrpcap, Raw
from labs.week_02.generator.packet_generator import PacketFactory

class TrafficGeneratorEngine:
    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        self.factory = PacketFactory()
        self.packets: List[Any] = []
        self.endpoints = {ep["id"]: ep for ep in self.config["endpoints"]}
        self.gateway_mac = self.config["gateway_mac"]
        self.gateway_ip = self.config["default_gateway"]

    def generate_web_session(self, client_id: str, server_id: str, domain: str = "srv-web-01.internal"):
        client = self.endpoints[client_id]
        server = self.endpoints[server_id]
        client_sport = random.randint(49152, 65500)
        client_seq = random.randint(1000, 50000)
        server_seq = random.randint(50001, 99999)
        tx_id = random.randint(1, 65535)

        # 1. DNS Query
        dns_req = (
            self.factory.build_ethernet(client["mac"], self.gateway_mac) /
            self.factory.build_ip(client["ip"], self.gateway_ip, "UDP") /
            self.factory.build_udp(client_sport, 53) /
            self.factory.build_dns_query(tx_id, domain)
        )
        # 2. DNS Answer
        dns_resp = (
            self.factory.build_ethernet(self.gateway_mac, client["mac"]) /
            self.factory.build_ip(self.gateway_ip, client["ip"], "UDP") /
            self.factory.build_udp(53, client_sport) /
            self.factory.build_dns_response(tx_id, domain, server["ip"])
        )
        self.packets.extend([dns_req, dns_resp])

        # 3. TCP 3-Way Handshake
        syn = (
            self.factory.build_ethernet(client["mac"], server["mac"]) /
            self.factory.build_ip(client["ip"], server["ip"], "TCP") /
            self.factory.build_tcp(client_sport, 80, flags="S", seq=client_seq)
        )
        syn_ack = (
            self.factory.build_ethernet(server["mac"], client["mac"]) /
            self.factory.build_ip(server["ip"], client["ip"], "TCP") /
            self.factory.build_tcp(80, client_sport, flags="SA", seq=server_seq, ack=client_seq + 1)
        )
        ack = (
            self.factory.build_ethernet(client["mac"], server["mac"]) /
            self.factory.build_ip(client["ip"], server["ip"], "TCP") /
            self.factory.build_tcp(client_sport, 80, flags="A", seq=client_seq + 1, ack=server_seq + 1)
        )
        self.packets.extend([syn, syn_ack, ack])

        # 4. HTTP Request + Response
        http_payload = b"GET /api/v1/twin HTTP/1.1\r\nHost: srv-web-01.internal\r\n\r\n"
        http_req = (
            self.factory.build_ethernet(client["mac"], server["mac"]) /
            self.factory.build_ip(client["ip"], server["ip"], "TCP") /
            self.factory.build_tcp(client_sport, 80, flags="PA", seq=client_seq + 1, ack=server_seq + 1) /
            Raw(load=http_payload)
        )
        http_resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ONLINE\"}"
        http_resp = (
            self.factory.build_ethernet(server["mac"], client["mac"]) /
            self.factory.build_ip(server["ip"], client["ip"], "TCP") /
            self.factory.build_tcp(80, client_sport, flags="PA", seq=server_seq + 1, ack=client_seq + 1 + len(http_payload)) /
            Raw(load=http_resp_payload)
        )
        self.packets.extend([http_req, http_resp])

        # 5. TCP 4-Way Teardown
        fin_client = (
            self.factory.build_ethernet(client["mac"], server["mac"]) /
            self.factory.build_ip(client["ip"], server["ip"], "TCP") /
            self.factory.build_tcp(client_sport, 80, flags="FA", seq=client_seq + 1 + len(http_payload), ack=server_seq + 1 + len(http_resp_payload))
        )
        ack_server = (
            self.factory.build_ethernet(server["mac"], client["mac"]) /
            self.factory.build_ip(server["ip"], client["ip"], "TCP") /
            self.factory.build_tcp(80, client_sport, flags="A", seq=server_seq + 1 + len(http_resp_payload), ack=client_seq + 2 + len(http_payload))
        )
        self.packets.extend([fin_client, ack_server])

    def generate_dns_heartbeats(self, count: int = 5):
        for i in range(count):
            client = self.endpoints["D001"]
            sport = random.randint(50000, 60000)
            tx_id = random.randint(100, 9999)
            pkt = (
                self.factory.build_ethernet(client["mac"], self.gateway_mac) /
                self.factory.build_ip(client["ip"], self.gateway_ip, "UDP") /
                self.factory.build_udp(sport, 53) /
                self.factory.build_dns_query(tx_id, f"node-{i}.internal.twin")
            )
            self.packets.append(pkt)

    def generate_icmp_reachability(self, count: int = 4):
        client = self.endpoints["D003"]
        server = self.endpoints["D002"]
        for seq in range(1, count + 1):
            echo_req = (
                self.factory.build_ethernet(client["mac"], server["mac"]) /
                self.factory.build_ip(client["ip"], server["ip"], "ICMP") /
                self.factory.build_icmp(icmp_type=8, icmp_id=0x55, seq=seq) /
                Raw(load=b"HEARTBEAT_ECHO_FRAME")
            )
            echo_rep = (
                self.factory.build_ethernet(server["mac"], client["mac"]) /
                self.factory.build_ip(server["ip"], client["ip"], "ICMP") /
                self.factory.build_icmp(icmp_type=0, icmp_id=0x55, seq=seq) /
                Raw(load=b"HEARTBEAT_ECHO_FRAME")
            )
            self.packets.extend([echo_req, echo_rep])

    def run_synthesis(self, output_pcap: str) -> int:
        print(f"[*] Executing traffic profile synthesis according to config...")
        profiles = self.config["profiles"]

        # Run Web Sessions
        for i in range(profiles.get("web_sessions_count", 2)):
            self.generate_web_session("D001", "D002")

        # Run DNS Heartbeats
        self.generate_dns_heartbeats(profiles.get("dns_heartbeats_count", 3))

        # Run ICMP Reachability
        self.generate_icmp_reachability(profiles.get("icmp_pings_count", 2))

        # Write sequential PCAP
        wrpcap(output_pcap, self.packets)
        print(f"[+] Total synthetic packets generated and committed: {len(self.packets)}")
        print(f"[+] PCAP file saved to: {output_pcap}")
        return len(self.packets)

if __name__ == "__main__":
    generator = TrafficGeneratorEngine("labs/week_02/generator/config.json")
    generator.run_synthesis("labs/week_02/pcap/synthetic_traffic.pcap")