import sys
from pathlib import Path
import random

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

class FirewallRule:
    def __init__(self, action: str, protocol: str, dst_port: int = None, src_ip_prefix: str = None):
        self.action = action # ALLOW, DROP
        self.protocol = protocol
        self.dst_port = dst_port
        self.src_ip_prefix = src_ip_prefix

    def matches(self, packet: dict) -> bool:
        if self.protocol != "ANY" and packet.get("protocol") != self.protocol:
            return False
        if self.dst_port and packet.get("dst_port") != self.dst_port:
            return False
        if self.src_ip_prefix and not packet.get("src_ip", "").startswith(self.src_ip_prefix):
            return False
        return True

class StatefulFirewall:
    def __init__(self):
        self.rules = []
        self.state_table = set() # (src_ip, src_port, dst_ip, dst_port, proto)

    def add_rule(self, rule: FirewallRule):
        self.rules.append(rule)

    def inspect_packet(self, packet: dict, direction: str) -> bool:
        session_key = (
            packet["src_ip"], packet["src_port"],
            packet["dst_ip"], packet["dst_port"],
            packet["protocol"]
        )
        reverse_session_key = (
            packet["dst_ip"], packet["dst_port"],
            packet["src_ip"], packet["src_port"],
            packet["protocol"]
        )

        # Allow returning established state
        if reverse_session_key in self.state_table:
            return True

        # Rule evaluation for outbound or new inbound flows
        for rule in self.rules:
            if rule.matches(packet):
                if rule.action == "ALLOW":
                    if direction == "OUTBOUND":
                        self.state_table.add(session_key)
                    return True
                return False

        # Implicit Deny
        return False

class NatRouterEngine:
    def __init__(self, public_wan_ip: str = "203.0.113.5"):
        self.public_wan_ip = public_wan_ip
        self.nat_table = {} # (private_ip, private_port) -> (public_ip, assigned_port)
        self.reverse_nat_table = {} # (public_ip, assigned_port) -> (private_ip, private_port)
        self.next_ephemeral_port = 40000

    def translate_outbound(self, packet: dict) -> dict:
        key = (packet["src_ip"], packet["src_port"])
        if key not in self.nat_table:
            allocated_port = self.next_ephemeral_port
            self.next_ephemeral_port += 1
            self.nat_table[key] = (self.public_wan_ip, allocated_port)
            self.reverse_nat_table[(self.public_wan_ip, allocated_port)] = key

        pub_ip, pub_port = self.nat_table[key]
        translated = packet.copy()
        translated["original_src"] = f"{packet['src_ip']}:{packet['src_port']}"
        translated["src_ip"] = pub_ip
        translated["src_port"] = pub_port
        return translated

    def translate_inbound(self, packet: dict) -> dict:
        key = (packet["dst_ip"], packet["dst_port"])
        if key in self.reverse_nat_table:
            priv_ip, priv_port = self.reverse_nat_table[key]
            translated = packet.copy()
            translated["dst_ip"] = priv_ip
            translated["dst_port"] = priv_port
            return translated
        return None

def run_simulation_demo():
    print("\n================= NETWORK ROUTING, NAT & FIREWALL LAB =================")
    firewall = StatefulFirewall()
    # Permit outbound web and internal traffic, drop unsolicited incoming traffic
    firewall.add_rule(FirewallRule(action="ALLOW", protocol="TCP", dst_port=443))
    firewall.add_rule(FirewallRule(action="ALLOW", protocol="TCP", dst_port=80))
    firewall.add_rule(FirewallRule(action="ALLOW", protocol="UDP", dst_port=53))

    router = NatRouterEngine(public_wan_ip="203.0.113.5")

    # Flow 1: Workstation PC1 requests HTTPS site on internet
    client_packet = {
        "src_ip": "192.168.1.11",
        "src_port": 52140,
        "dst_ip": "93.184.216.34",
        "dst_port": 443,
        "protocol": "TCP"
    }
    print(f"\n[1. CLIENT EGRESS] PC1 Transmitting: {client_packet['src_ip']}:{client_packet['src_port']} -> {client_packet['dst_ip']}:{client_packet['dst_port']}")

    # Check firewall
    allowed = firewall.inspect_packet(client_packet, direction="OUTBOUND")
    print(f"[2. FIREWALL EVALUATION] Outbound Filter Check: {'PERMITTED' if allowed else 'BLOCKED'}")

    # NAT Translation
    translated_packet = router.translate_outbound(client_packet)
    print(f"[3. NAT REWRITE] Post-NAT Egress Packet: {translated_packet['src_ip']}:{translated_packet['src_port']} -> {translated_packet['dst_ip']}:{translated_packet['dst_port']}")

    # Returning traffic from WAN Server
    server_return_packet = {
        "src_ip": "93.184.216.34",
        "src_port": 443,
        "dst_ip": translated_packet["src_ip"],
        "dst_port": translated_packet["src_port"],
        "protocol": "TCP"
    }
    print(f"\n[4. SERVER INBOUND] WAN Server Replies: {server_return_packet['src_ip']}:{server_return_packet['src_port']} -> {server_return_packet['dst_ip']}:{server_return_packet['dst_port']}")

    # Inbound Firewall evaluation (Stateful check)
    inbound_allowed = firewall.inspect_packet(server_return_packet, direction="INBOUND")
    print(f"[5. STATEFUL FIREWALL] Inbound Filter Check: {'PERMITTED (MATCHED ACTIVE STATE)' if inbound_allowed else 'BLOCKED'}")

    # Inbound NAT reverse translation
    final_client_packet = router.translate_inbound(server_return_packet)
    print(f"[6. NAT REVERSE MAPPING] Delivered to Client: {final_client_packet['dst_ip']}:{final_client_packet['dst_port']}")

if __name__ == "__main__":
    run_simulation_demo()