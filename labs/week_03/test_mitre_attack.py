import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.siem_engine import siem_engine
from packages.shared_types.src.events import SecurityEvent

def run_mitre_test():
    print("================================================================================")
    print("      WEEK 3 - DAY 19: MITRE ATT&CK ADVERSARY BEHAVIOR MAPPING LAB              ")
    print("================================================================================\n")

    bootstrap_security_grounding()

    test_scenarios = [
        {
            "desc": "Stage 1: Active Inbound Port Reconnaissance",
            "event": SecurityEvent(
                source_ip="192.168.1.99",
                destination_ip="192.168.1.10",
                destination_port=4444,
                protocol="TCP",
                event_type="SCAN_RECON_PROBE",
                severity="MEDIUM"
            ),
            "expected_tactic": "TA0043",
            "expected_technique": "T1595.001"
        },
        {
            "desc": "Stage 2: Remote Shell Exploit Injection",
            "event": SecurityEvent(
                source_ip="192.168.1.99",
                destination_ip="192.168.1.10",
                destination_port=22,
                protocol="TCP",
                event_type="EXPLOIT_SHELL_COMMAND",
                severity="CRITICAL",
                details={"cve": "CVE-2023-38408"}
            ),
            "expected_tactic": "TA0002",
            "expected_technique": "T1059.004"
        },
        {
            "desc": "Stage 3: SSH Credential Guessing / Brute Force",
            "event": SecurityEvent(
                source_ip="192.168.1.99",
                destination_ip="192.168.1.10",
                destination_port=22,
                protocol="TCP",
                event_type="AUTH_BRUTE_FORCE_FAILURE",
                severity="HIGH"
            ),
            "expected_tactic": "TA0006",
            "expected_technique": "T1110.001"
        },
        {
            "desc": "Stage 4: Lateral Movement Pivot from Compromised D002 to D003",
            "event": SecurityEvent(
                source_ip="192.168.1.10", # Compromised srv-web-01
                destination_ip="192.168.1.12", # Target ws-pc-02
                destination_port=22,
                protocol="TCP",
                event_type="LATERAL_TRAVERSAL_ATTEMPT",
                severity="HIGH"
            ),
            "expected_tactic": "TA0008",
            "expected_technique": "T1021.004"
        }
    ]

    for idx, test in enumerate(test_scenarios, start=1):
        print(f"[{idx}/4] Testing {test['desc']}...")
        result = siem_engine.ingest_security_event(test["event"])
        mapping = result["mitre_attack"]
        
        assert mapping is not None, f"Failed to generate ATT&CK mapping for {test['event'].event_type}"
        print(f"    [+] Tactic    : {mapping['tactic_id']} - {mapping['tactic_name']}")
        print(f"    [+] Technique : {mapping['technique_id']} - {mapping['technique_name']}")
        print(f"    [+] Evidence  : {mapping['evidence']}")
        print(f"    [+] Confidence: {mapping['confidence'] * 100:.1f}%\n")

        assert mapping["tactic_id"] == test["expected_tactic"], f"Expected tactic {test['expected_tactic']}, got {mapping['tactic_id']}"
        assert mapping["technique_id"] == test["expected_technique"], f"Expected technique {test['expected_technique']}, got {mapping['technique_id']}"

    print("--- ACTIVE INCIDENT SUMMARY ---")
    incidents = siem_engine.active_incidents
    print(f"Total Correlated Multi-Stage Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"  - [{inc['severity']}] {inc['incident_id']}: {inc['title']}")
        print(f"    Tactics Linked: {inc.get('mitre_tactics')}")

    print("\n[+] All 4 MITRE ATT&CK stages mapped and verified with evidence trails.")

if __name__ == "__main__":
    run_mitre_test()