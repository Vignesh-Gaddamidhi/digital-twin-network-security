import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.graph_models import NodeTypeEnum
from services.digital_twin.attack_path.graph.security_zone_models import (
    NetworkZoneEnum, ReachabilityStateEnum
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer

def run_day135_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 135: SECURITY-AWARE DIGITAL TWIN GRAPH SYNC AUDIT")
    print("=" * 80 + "\n")

    # 1. Device Synchronization
    print("[1/11] Auditing Device Registry Synchronization into Graph Nodes...")
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    assert len(attack_path_graph.nodes) == 5
    client = attack_path_graph.get_node("CLIENT-01")
    web = attack_path_graph.get_node("WEB-01")
    db = attack_path_graph.get_node("DB-01")

    print(f"    CLIENT-01 Node : Host={client.hostname:<24} | Crit={client.assetCriticality:<8} | IP={client.ipAddresses[0]}")
    print(f"    WEB-01    Node : Host={web.hostname:<24} | Crit={web.assetCriticality:<8} | IP={web.ipAddresses[0]}")
    print(f"    DB-01     Node : Host={db.hostname:<24} | Crit={db.assetCriticality:<8} | IP={db.ipAddresses[0]}")

    assert client.deviceId == "CLIENT-01"
    assert web.assetCriticality == "HIGH"
    assert db.assetCriticality == "CRITICAL"
    print("    [PASS] Digital Twin devices successfully synchronized into graph.")

    # 2. Connection Synchronization
    print("\n[2/11] Auditing Digital Twin Connection Synchronization into Directed Edges...")
    assert len(attack_path_graph.edges) == 5
    print(f"    Synced Edge Count : {len(attack_path_graph.edges)}")
    assert "CONN-01" in attack_path_graph.edges
    assert "CONN-03" in attack_path_graph.edges
    print("    [PASS] Digital Twin connection records mapped to directed graph edges.")

    # 3. Zone Synchronization
    print("\n[3/11] Auditing Network Zone Attribution on Nodes...")
    print(f"    ATTACKER-EXT Zone : {attack_path_graph.get_node('ATTACKER-EXT').zone}")
    print(f"    WEB-01       Zone : {web.zone}")
    print(f"    CLIENT-01    Zone : {client.zone}")
    print(f"    DB-01        Zone : {db.zone}")

    assert attack_path_graph.get_node("ATTACKER-EXT").zone == NetworkZoneEnum.INTERNET.value
    assert web.zone == NetworkZoneEnum.DMZ.value
    assert client.zone == NetworkZoneEnum.INTERNAL.value
    assert db.zone == NetworkZoneEnum.DATABASE.value
    print("    [PASS] Network zones accurately assigned across all nodes.")

    # 4. Vulnerability Synchronization
    print("\n[4/11] Auditing Vulnerability Synchronization...")
    print(f"    WEB-01 Vulnerabilities : {web.vulnerabilities}")
    print(f"    DB-01  Vulnerabilities : {db.vulnerabilities}")
    assert "CVE-2026-WEB-RCE" in web.vulnerabilities
    assert "CVE-2026-SQLI" in db.vulnerabilities
    print("    [PASS] Known vulnerabilities synchronized.")

    # 5. Port & Service Synchronization
    print("\n[5/11] Auditing Port and Service Exposure Synchronization...")
    print(f"    WEB-01 Ports    : {web.exposedPorts} | Services: {web.services}")
    print(f"    DB-01  Ports    : {db.exposedPorts} | Services: {db.services}")
    assert 443 in web.exposedPorts
    assert 22 in web.exposedPorts
    assert 3306 in db.exposedPorts
    assert "MYSQL" in db.services
    print("    [PASS] Exposed ports and services synchronized.")

    # 6. Security-State & Risk Score Synchronization
    print("\n[6/11] Auditing Security State and Risk Synchronization...")
    print(f"    WEB-01 Security State : {web.securityState:<10} | Risk Score: {web.riskScore:.2f}")
    print(f"    DB-01  Security State : {db.securityState:<10} | Risk Score: {db.riskScore:.2f}")
    assert web.securityState == "AT_RISK"
    assert web.riskScore == 60.80
    assert db.riskScore == 69.60
    print("    [PASS] Security states and risk scores mapped from Twin.")

    # 7. Reachability State & Security Controls Enforcement
    print("\n[7/11] Auditing Reachability & Firewall Segmentation Enforcement...")
    edge_web_db = attack_path_graph.edges["CONN-03"]
    edge_client_db = attack_path_graph.edges["CONN-05"]

    print(f"    WEB-01 -> DB-01 (TCP 3306)    : Reachable={edge_web_db.reachable} | Status={edge_web_db.status} ({edge_web_db.securityControl})")
    print(f"    CLIENT-01 -> DB-01 (TCP 3306) : Reachable={edge_client_db.reachable} | Status={edge_client_db.status} ({edge_client_db.securityControl})")

    assert edge_web_db.reachable is True
    assert edge_web_db.status == ReachabilityStateEnum.REACHABLE.value
    assert edge_client_db.reachable is False
    assert edge_client_db.status == ReachabilityStateEnum.BLOCKED.value
    print("    [PASS] Security control policies strictly enforce reachability vs blocked states.")

    # 8. Graph Update After Device Change (Port Added)
    print("\n[8/11] Auditing Graph Reactive Update After Device Change (Opening Port 8080)...")
    twin_graph_synchronizer.update_device_ports("WEB-01", [80, 443, 22, 8080])
    updated_web = attack_path_graph.get_node("WEB-01")
    print(f"    WEB-01 Updated Ports: {updated_web.exposedPorts}")
    assert 8080 in updated_web.exposedPorts
    print("    [PASS] Device mutation automatically refreshed graph projection.")

    # 9. Graph Update After Connection Added and Removed
    print("\n[9/11] Auditing Graph Reactive Update After Connection Changes...")
    new_conn = {
        "connectionId": "CONN-TEMP-99",
        "sourceDevice": "CLIENT-01",
        "destinationDevice": "WEB-01",
        "protocol": "TCP",
        "destinationPort": 80,
        "service": "HTTP",
        "status": "ESTABLISHED"
    }
    twin_graph_synchronizer.sync_connection(new_conn)
    assert "CONN-TEMP-99" in attack_path_graph.edges
    print("    Added CONN-TEMP-99 successfully.")

    twin_graph_synchronizer.remove_connection("CONN-TEMP-99")
    assert "CONN-TEMP-99" not in attack_path_graph.edges
    print("    Removed CONN-TEMP-99 successfully.")
    print("    [PASS] Dynamic connection lifecycle verified.")

    # 10. Graph Update After Vulnerability Patched
    print("\n[10/11] Auditing Graph Reactive Update After Vulnerability Remediation...")
    twin_graph_synchronizer.update_device_vulnerabilities("WEB-01", [])
    patched_web = attack_path_graph.get_node("WEB-01")
    print(f"    WEB-01 Vulnerabilities after Patching: {patched_web.vulnerabilities}")
    assert len(patched_web.vulnerabilities) == 0
    print("    [PASS] Vulnerability patching synchronized.")

    # 11. Automated Device Quarantine / Isolation
    print("\n[11/11] Auditing Automated Host Quarantine (CLIENT-01)...")
    twin_graph_synchronizer.isolate_device("CLIENT-01")
    quarantined_client = attack_path_graph.get_node("CLIENT-01")
    print(f"    CLIENT-01 Security State : {quarantined_client.securityState}")
    remaining_client_edges = [
        e for e in attack_path_graph.edges.values()
        if e.sourceNode == "CLIENT-01" or e.destinationNode == "CLIENT-01"
    ]
    print(f"    Remaining Edges for CLIENT-01: {len(remaining_client_edges)}")

    assert quarantined_client.securityState == "QUARANTINED"
    assert len(remaining_client_edges) == 0
    print("    [PASS] Device isolation immediately severed all incident graph edges.")

    # Verify Disk Snapshot
    snap_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path" / "twin_synced_graph.json"
    assert snap_file.exists()
    print("    [PASS] Synced graph snapshot verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 135 TWIN GRAPH SYNCHRONIZATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day135_suite()