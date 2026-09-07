import random
from typing import Optional
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw

class PacketFactory:
    """Creates deterministic protocol frames aligned with the Digital Twin schema."""

    @staticmethod
    def build_ethernet(src_mac: str, dst_mac: str) -> Ether:
        return Ether(src=src_mac, dst=dst_mac)

    @staticmethod
    def build_ip(src_ip: str, dst_ip: str, proto: str, ttl: int = 64) -> IP:
        proto_num = 6 if proto == "TCP" else 17 if proto == "UDP" else 1
        return IP(src=src_ip, dst=dst_ip, ttl=ttl, proto=proto_num)

    @staticmethod
    def build_tcp(sport: int, dport: int, flags: str, seq: int, ack: int = 0) -> TCP:
        return TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=65535)

    @staticmethod
    def build_udp(sport: int, dport: int) -> UDP:
        return UDP(sport=sport, dport=dport)

    @staticmethod
    def build_dns_query(tx_id: int, query_domain: str) -> DNS:
        return DNS(id=tx_id, rd=1, qd=DNSQR(qname=query_domain))

    @staticmethod
    def build_dns_response(tx_id: int, query_domain: str, answer_ip: str) -> DNS:
        return DNS(
            id=tx_id, qr=1, aa=1, rd=1,
            qd=DNSQR(qname=query_domain),
            an=DNSRR(rrname=query_domain, type="A", rdata=answer_ip, ttl=300)
        )

    @staticmethod
    def build_icmp(icmp_type: int = 8, icmp_id: int = 1, seq: int = 1) -> ICMP:
        return ICMP(type=icmp_type, code=0, id=icmp_id, seq=seq)