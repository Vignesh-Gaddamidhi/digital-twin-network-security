import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.siem_engine import siem_engine
from packages.shared_types.src.events import SecurityEvent

def run_siem_test():
    print("================================================================================")
    print("      WEEK 3 - DAY 18: SIEM LOG CORRELATION & SOC INCIDENT PIPELINE             ")
    print("================================================================================\n")

    # Bootstrap baseline canonical topology
    bootstrap_security_grounding()
    web_server = twin_engine.node_registry["D002"]
    print(f"[*] Initial Baseline for {web_server.hostname} ({web_server.id}):")
    print(f"    Security State: {web_server.security_state} | CIA C={web_server.cia_score.confidentiality}")

    # Event 1: Reconnaissance Scan Detected by IDS
    print("\n[1/3] Ingesting Stage 1 SecurityEvent: Reconnaissance Scan Probe...")
    evt1 = SecurityEvent(
        source_ip="192.168.1.99",
        destination_ip="192.168.1.10",
        source_port=58912,
        destination_port=4444,
        protocol="TCP",
        event_type="SCAN_RECON_PROBE",
        severity="MEDIUM",
        confidence=0.90,
        detection_source="SURICATA_NIDS"
    )
    res1 = siem_engine.ingest_security_event(evt1)
    print(f"    Event Ingested: {res1['event_id']} (Dest Mapped: {res1['destination_device']})")
    assert res1["destination_device"] == "D002", "Failed to resolve destination device D002"
    assert res1["correlated_incident"] is None, "Isolated scan should not trigger correlated incident yet"

    # Event 2: Weaponized Exploit Shell Injection Detected 5 seconds later
    print("\n[2/3] Ingesting Stage 2 SecurityEvent: Exploit Payload Delivery...")
    evt2 = SecurityEvent(
        source_ip="192.168.1.99",
        destination_ip="192.168.1.10",
        source_port=58914,
        destination_port=22,
        protocol="TCP",
        event_type="EXPLOIT_SHELL_COMMAND_ATTEMPT",
        severity="CRITICAL",
        confidence=0.98,
        detection_source="SURICATA_NIDS",
        details={"cve": "CVE-2023-38408"}
    )
    res2 = siem_engine.ingest_security_event(evt2)
    print(f"    Event Ingested: {res2['event_id']}")
    
    # 3. Validate Incident Correlation
    print("\n[3/3] Auditing SIEM Multi-Event Correlation & Digital Twin State Impact...")
    incident = res2["correlated_incident"]
    assert incident is not None, "SIEM Engine failed to correlate multi-stage attack incident!"
    print(f"    [+] Active Incident Triggered: {incident['incident_id']}")
    print(f"    [+] Incident Title          : {incident['title']}")
    print(f"    [+] Severity Level          : {incident['severity']}")
    print(f"    [+] Correlated Event IDs    : {incident['events_involved']}")

    # Validate Digital Twin State Synchronization
    updated_web = twin_engine.node_registry["D002"]
    print(f"\n[*] Synchronized Digital Twin State for D002:")
    print(f"    Security State: {updated_web.security_state}")
    print(f"    CIA Degradation: C={updated_web.cia_score.confidentiality}, I={updated_web.cia_score.integrity}, A={updated_web.cia_score.availability}")
    assert updated_web.security_state == "COMPROMISED", "D002 should transition to COMPROMISED following critical exploit event"

    print("\n[+] SIEM multi-source correlation and Digital Twin synchronization verified successfully.")

if __name__ == "__main__":
    run_siem_test()