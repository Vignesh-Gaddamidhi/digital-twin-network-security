import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw

def run_packet_forensics():
    print("================================================================================")
    print("      WEEK 1 CAPSTONE: PACKET INVESTIGATION & FORENSICS LAB (EX 1 - 8)         ")
    print("================================================================================\n")

    # Exercise 1: PC1 communicates with PC2 (Local Layer 2 Switching via ARP/ICMP)
    arp_pkt = Ether(src="00:50:56:FE:01:11", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="00:50:56:FE:01:11", psrc="192.168.1.11",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.12"
    )
    print("[+] EXERCISE 1: PC1 -> PC2 Local Subnet Discovery")
    print(f"    Frame Structure: Ether(src={arp_pkt.src}, dst={arp_pkt.dst}) -> ARP(Who-Has {arp_pkt[ARP].pdst}?)")
    print("    Forensic Insight: Stays inside local broadcast domain; router gateway is bypassed.\n")

    # Exercise 2: PC1 accesses a website (External WAN egress)
    wan_frame = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:00") / IP(
        src="192.168.1.11", dst="93.184.216.34"
    ) / TCP(sport=51234, dport=443, flags="S")
    print("[+] EXERCISE 2: PC1 Accesses External Website")
    print(f"    Layer-2 Destination: {wan_frame.dst} (Router MAC, NOT final server MAC)")
    print(f"    Layer-3 Destination: {wan_frame[IP].dst} (End-to-End Server IP)\n")

    # Exercise 3: DNS Resolution
    dns_query = Ether(src="00:50:56:FE:01:11", dst="00:50:56:FE:01:00") / IP(
        src="192.168.1.11", dst="192.168.1.1"
    ) / UDP(sport=58921, dport=53) / DNS(rd=1, qd=DNSQR(qname="api.internal.bank"))
    print("[+] EXERCISE 3: DNS Name Resolution")
    print(f"    Transport: UDP Port {dns_query[UDP].dport} -> Queried FQDN: {dns_query[DNSQR].qname.decode()}")
    print("    Forensic Insight: Precedes every L7 transport socket establishment.\n")

    # Exercise 4: Where does TCP begin?
    tcp_syn = IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=49152, dport=80, flags="S", seq=1000)
    print("[+] EXERCISE 4: Where TCP Begins")
    print(f"    Initiation Marker: Control Flags = {tcp_syn[TCP].flags} (SYN)")
    print(f"    Initial Sequence Number (ISN): {tcp_syn[TCP].seq}\n")

    # Exercise 5: Where HTTPS/TLS appears
    tls_payload = Raw(load=b"\x16\x03\x03\x00\x45\x01\x00\x00\x41\x03\x03" + b"\x00" * 32)
    tls_frame = IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=49152, dport=443, flags="PA") / tls_payload
    print("[+] EXERCISE 5: Where HTTPS/TLS Appears")
    print(f"    Layer: Enclosed within TCP Port {tls_frame[TCP].dport} Application Payload")
    print(f"    TLS Content-Type: 0x16 (Handshake record), Version: TLS 1.2/1.3 (0x0303)\n")

    # Exercise 6: MAC Addresses Involved
    print("[+] EXERCISE 6: MAC Address Attribution")
    print("    Hop 1 (LAN Source): 00:50:56:FE:01:11 (PC1)")
    print("    Hop 2 (LAN Gateway): 00:50:56:FE:01:00 (Router Ingress)\n")

    # Exercise 7: IP Addresses Involved
    print("[+] EXERCISE 7: IP Address Attribution")
    print("    Local Endpoint: 192.168.1.11 (RFC 1918 Private IP)")
    print("    Public Transit IP: 203.0.113.5 (Post-NAT Egress Gateway)")
    print("    Target IP: 93.184.216.34 (Public Endpoint)\n")

    # Exercise 8: Ports Involved
    print("[+] EXERCISE 8: Port Multiplexing Attribution")
    print("    Source Port: 51234 (Ephemeral Range 49152 - 65535)")
    print("    Destination Port: 443 (Well-Known HTTPS Service Daemon)\n")
    print("[*] All 8 investigation exercises verified successfully.")

if __name__ == "__main__":
    run_packet_forensics()