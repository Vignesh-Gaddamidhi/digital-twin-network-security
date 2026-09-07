import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.core.twin_state import twin_engine, DeviceEntity, DeviceInterface
from packages.shared_types.src.security import VulnerabilityEntity, CIAScore

def run_cia_test():
    print("================================================================================")
    print("       WEEK 3 - DAY 15: CIA TRIAD IMPACT SIMULATION & STATE ENGINE              ")
    print("================================================================================\n")

    # 1. Setup Test Device
    test_node = DeviceEntity(
        id="D002",
        hostname="srv-web-01",
        type="SERVER",
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.10", mac_address="00:50:56:FE:01:10", subnet="192.168.1.0/24")],
        open_ports=[80, 443, 22],
        services=["nginx/1.24", "openssh-8.9"],
        vulnerabilities=[
            VulnerabilityEntity(
                cve_id="CVE-2023-38408",
                description="OpenSSH PKCS#11 Provider RCE",
                cvss_score=9.8,
                affected_service="openssh-8.9",
                port=22,
                remediation="Upgrade to 9.3p2"
            )
        ],
        criticality=8.5
    )
    twin_engine.add_or_update_node(test_node)
    print(f"[*] Base State for {test_node.hostname} ({test_node.id}):")
    print(f"    Security State: {test_node.security_state} | Criticality: {test_node.criticality}")
    print(f"    CIA Posture   : C={test_node.cia_score.confidentiality}, I={test_node.cia_score.integrity}, A={test_node.cia_score.availability}\n")

    # 2. Stage 1 Attack Simulation: Confidentiality Leak (Data Exfiltration)
    print("[+] STAGE 1: Simulating Data Exfiltration against D002 (-0.4 Confidentiality)...")
    twin_engine.degrade_cia("D002", "CONFIDENTIALITY", 0.4)
    updated = twin_engine.node_registry["D002"]
    print(f"    Security State: {updated.security_state} (CIA C={updated.cia_score.confidentiality})")
    assert updated.security_state == "SUSPICIOUS", "State should be SUSPICIOUS after 0.4 leak"

    # 3. Stage 2 Attack Simulation: Availability Destruction (DDoS / Service Crash)
    print("\n[+] STAGE 2: Simulating Remote Code Execution Crash (-0.8 Availability)...")
    twin_engine.degrade_cia("D002", "AVAILABILITY", 0.8)
    updated = twin_engine.node_registry["D002"]
    print(f"    Security State: {updated.security_state} (CIA A={updated.cia_score.availability})")
    assert updated.security_state == "COMPROMISED", "State should be COMPROMISED after critical availability collapse"

    print("\n[+] CIA degradation and dynamic security state transitions verified successfully.")

if __name__ == "__main__":
    run_cia_test()