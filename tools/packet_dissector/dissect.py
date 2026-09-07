import sys
from datetime import datetime
from scapy.all import IP, TCP, UDP, Ether, DNS, Raw, conf

def inspect_packet_layers(pkt):
    print("\n" + "="*80)
    print(f"PACKET CAPTURED: {datetime.now().isoformat()}")
    print("="*80)

    # 1. Physical / Link Layer (OSI Layer 2 / TCP-IP Network Access)
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print("\n[+] [OSI L2 - DATA LINK / TCP-IP NETWORK ACCESS]")
        print(f"    Source MAC      : {eth.src}")
        print(f"    Destination MAC : {eth.dst}")
        print(f"    EtherType       : {hex(eth.type)}")

    # 2. Network Layer (OSI Layer 3 / TCP-IP Internet Layer)
    if pkt.haslayer(IP):
        ip = pkt[IP]
        print("\n[+] [OSI L3 - NETWORK / TCP-IP INTERNET]")
        print(f"    Source IP       : {ip.src}")
        print(f"    Destination IP  : {ip.dst}")
        print(f"    Protocol Number : {ip.proto} ({'TCP' if ip.proto==6 else 'UDP' if ip.proto==17 else 'OTHER'})")
        print(f"    TTL (Hop Limit) : {ip.ttl}")
        print(f"    Packet Length   : {ip.len} bytes")

    # 3. Transport Layer (OSI Layer 4 / TCP-IP Transport)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        print("\n[+] [OSI L4 - TRANSPORT (TCP)]")
        print(f"    Source Port     : {tcp.sport}")
        print(f"    Destination Port: {tcp.dport}")
        print(f"    Sequence Number : {tcp.seq}")
        print(f"    Ack Number      : {tcp.ack}")
        print(f"    Control Flags   : {tcp.flags}")
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        print("\n[+] [OSI L4 - TRANSPORT (UDP)]")
        print(f"    Source Port     : {udp.sport}")
        print(f"    Destination Port: {udp.dport}")
        print(f"    Length          : {udp.len}")

    # 4. Application Layer (OSI Layer 7 / TCP-IP Application)
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        print("\n[+] [OSI L7 - APPLICATION (DNS)]")
        print(f"    Transaction ID  : {hex(dns.id)}")
        print(f"    Query/Response  : {'Response' if dns.qr == 1 else 'Query'}")
        if dns.qd:
            print(f"    DNS Query Name  : {dns.qd.qname.decode('utf-8', errors='ignore')}")
    elif pkt.haslayer(Raw):
        raw = pkt[Raw].load
        print("\n[+] [OSI L7 - APPLICATION (RAW PAYLOAD)]")
        snippet = raw[:120].decode("utf-8", errors="replace").replace("\r\n", " ")
        print(f"    Payload Snippet : {snippet}")

def run_synthetic_dissection():
    """Generates and dissects deterministic in-memory frames without requiring Npcap drivers."""
    from scapy.all import IP, TCP, Ether, Raw
    print("\n--- RUNNING DETERMINISTIC PACKET DISSECTION ENGINE ---")
    
    synthetic_frame = (
        Ether(src="00:1A:2B:3C:4D:01", dst="AA:BB:CC:DD:EE:FF") /
        IP(src="192.168.1.11", dst="192.168.1.10", ttl=64) /
        TCP(sport=51234, dport=80, flags="PA", seq=1001, ack=2001) /
        Raw(load=b"GET /api/v1/health HTTP/1.1\r\nHost: twin.internal\r\n\r\n")
    )
    inspect_packet_layers(synthetic_frame)

if __name__ == "__main__":
    run_synthetic_dissection()