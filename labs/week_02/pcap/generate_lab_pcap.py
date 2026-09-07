import sys
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

def generate_lab_pcap(output_path: str = "labs/week_02/pcap/lab_sample.pcap"):
    print(f"[*] Generating mixed-protocol capture to: {output_path}")
    packets = []

    # 1. TCP 3-Way Handshake + HTTP GET
    syn = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=51000, dport=80, flags="S", seq=100)
    syn_ack = Ether(src="00:50:56:FE:01:10", dst="00:50:56:FE:01:11") / IP(src="192.168.1.10", dst="192.168.1.11") / TCP(sport=80, dport=51000, flags="SA", seq=500, ack=101)
    ack = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=51000, dport=80, flags="A", seq=101, ack=501)
    http_get = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=51000, dport=80, flags="PA", seq=101, ack=501) / Raw(load=b"GET /api/v1/twin HTTP/1.1\r\nHost: twin.internal\r\n\r\n")
    packets.extend([syn, syn_ack, ack, http_get])

    # 2. DNS Query & Response
    dns_query = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:00") / IP(src="192.168.1.11", dst="192.168.1.1") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="security.twin.internal"))
    packets.append(dns_query)

    # 3. TLS ClientHello Simulation
    tls_blob = b"\x16\x03\x03\x00\x2f\x01\x00\x00\x2b\x03\x03" + b"\xaa" * 32
    tls_packet = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=52000, dport=443, flags="PA", seq=200, ack=600) / Raw(load=tls_blob)
    packets.append(tls_packet)

    # 4. ICMP Echo Request
    icmp_pkt = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:10") / IP(src="192.168.1.11", dst="192.168.1.10") / ICMP(type=8, code=0)
    packets.append(icmp_pkt)

    # 5. UDP Telemetry Burst
    udp_burst = Ether(src="00:50:56:FE:01:12", dst="00:50:56:FE:01:10") / IP(src="192.168.1.12", dst="192.168.1.10") / UDP(sport=60000, dport=6000) / Raw(load=b"LOG_EVENT:SYS_REBOOT")
    packets.append(udp_burst)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path}")

if __name__ == "__main__":
    generate_lab_pcap()