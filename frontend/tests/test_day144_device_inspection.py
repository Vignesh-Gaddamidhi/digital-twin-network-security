import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.dashboard.device_inspection_models import (
    EpistemicProvenanceEnum, DeviceResourceUtilization, DeviceSearchQuery
)
from frontend.dashboard.device_inspection_engine import device_inspection_engine

def run_day144_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 144: LIVE DIGITAL TWIN STATE & DEVICE INSPECTION AUDIT")
    print("=" * 80 + "\n")

    # Baseline seed
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. Device Inspection Panel Data Extraction (WEB-01)
    print("[1/8] Auditing Live Device Detail Inspection Panel (WEB-01)...")
    detail = device_inspection_engine.get_live_device_detail("WEB-01")
    panel_cli = detail.to_formatted_cli_panel()
    print(panel_cli)

    assert detail.deviceId == "WEB-01"
    assert detail.zone == "DMZ"
    assert detail.utilization.cpuPercent == 42.0
    assert detail.utilization.activeConnectionCount == 18
    assert 443 in detail.openPorts
    assert "CVE-2026-WEB-RCE" in detail.activeVulnerabilities
    print("    [PASS] Device inspection panel rendered with full telemetry.")

    # 2. Telemetry Updates
    print("\n[2/8] Auditing Dynamic Telemetry Vitals Injection...")
    new_util = DeviceResourceUtilization(
        cpuPercent=88.4,
        memoryPercent=92.1,
        networkUtilizationPercent=75.0,
        packetRatePerSec=1450.0,
        byteRatePerSec=348000.0,
        activeConnectionCount=42
    )
    device_inspection_engine.update_telemetry("WEB-01", new_util)
    updated_detail = device_inspection_engine.get_live_device_detail("WEB-01")

    print(f"    Updated CPU: {updated_detail.utilization.cpuPercent}% | Packets/s: {updated_detail.utilization.packetRatePerSec}")
    assert updated_detail.utilization.cpuPercent == 88.4
    assert updated_detail.utilization.packetRatePerSec == 1450.0
    print("    [PASS] Telemetry vitals updated dynamically.")

    # 3. Historical State Tracking (Chronological Progression)
    print("\n[3/8] Auditing Chronological State Transition History...")
    history = updated_detail.stateHistory
    print(f"    State Sequence: {' -> '.join(h.status for h in history)}")
    assert len(history) >= 4
    assert history[0].status == "NORMAL"
    assert history[-1].status == "AT_RISK"
    print("    [PASS] Four-stage security state progression validated.")

    # 4. Epistemic Provenance: Real Telemetry vs Simulation vs Predicted
    print("\n[4/8] Auditing Ground Truth Provenance Tagging...")
    att_detail = device_inspection_engine.get_live_device_detail("ATTACKER-EXT")
    web_detail = device_inspection_engine.get_live_device_detail("WEB-01")

    print(f"    ATTACKER-EXT Provenance : {att_detail.provenance.value}")
    print(f"    WEB-01       Provenance : {web_detail.provenance.value}")

    assert att_detail.provenance == EpistemicProvenanceEnum.REAL_TELEMETRY
    assert web_detail.provenance == EpistemicProvenanceEnum.SIMULATION

    # Test setting Predicted provenance
    device_inspection_engine.set_device_provenance("CLIENT-01", EpistemicProvenanceEnum.PREDICTED)
    client_detail = device_inspection_engine.get_live_device_detail("CLIENT-01")
    assert client_detail.provenance == EpistemicProvenanceEnum.PREDICTED
    print("    [PASS] REAL, SIMULATION, and PREDICTED ground truth tags strictly decoupled.")

    # 5. Device Search (By ID)
    print("\n[5/8] Auditing Device Search by ID ('DB-01')...")
    res_id = device_inspection_engine.search_devices(DeviceSearchQuery(query="DB-01"))
    assert len(res_id) == 1
    assert res_id[0].deviceId == "DB-01"
    print(f"    Matched: {res_id[0].deviceId} ({res_id[0].hostname})")
    print("    [PASS] Search by Device ID verified.")

    # 6. Device Search (By IP Address)
    print("\n[6/8] Auditing Device Search by IP ('192.168.30.10')...")
    res_ip = device_inspection_engine.search_devices(DeviceSearchQuery(query="192.168.30.10"))
    assert len(res_ip) == 1
    assert res_ip[0].deviceId == "DB-01"
    print(f"    Matched: {res_ip[0].deviceId} on IP {res_ip[0].ipAddresses}")
    print("    [PASS] Search by IP verified.")

    # 7. Device Search (By Service Name)
    print("\n[7/8] Auditing Device Search by Service ('MYSQL')...")
    res_srv = device_inspection_engine.search_devices(DeviceSearchQuery(query="MYSQL"))
    matched_ids = [m.deviceId for m in res_srv]
    print(f"    Matched Devices with MySQL: {matched_ids}")
    assert "DB-01" in matched_ids
    print("    [PASS] Search by service name verified.")

    # 8. Combined Multi-Attribute Filter Query
    print("\n[8/8] Auditing Combined Filter Search (Zone=DMZ, minRiskScore=50.0)...")
    res_comb = device_inspection_engine.search_devices(DeviceSearchQuery(zone="DMZ", minRiskScore=50.0))
    print(f"    Matched DMZ Hosts with Risk >= 50.0: {[m.deviceId for m in res_comb]}")
    assert len(res_comb) == 1
    assert res_comb[0].deviceId == "WEB-01"
    print("    [PASS] Multi-attribute criteria filter verified.")

    # Reset environment
    device_inspection_engine._seed_default_telemetry()

    print("\n" + "=" * 80)
    print("       ALL DAY 144 DEVICE INSPECTION & TELEMETRY TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day144_suite()