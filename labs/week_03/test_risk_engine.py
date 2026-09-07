import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.risk_engine import risk_engine

def run_risk_audit():
    print("================================================================================")
    print("       WEEK 3 - DAY 16: ATTACK SURFACE & DYNAMIC RISK ENGINE AUDIT              ")
    print("================================================================================\n")

    # Bootstrap baseline topology with vulnerabilities
    bootstrap_security_grounding()

    # 1. Evaluate baseline ambient risk (Threat prob = 0.2)
    assessments = risk_engine.evaluate_entire_topology(ambient_threat_prob=0.2)

    print(f"{'Node ID':8s} {'Hostname':14s} {'Risk Score':12s} {'Severity':10s} {'Max CVSS':10s} {'Exposure':10s}")
    print("-" * 70)
    for a in assessments:
        m = a["metrics"]
        print(f"{a['node_id']:8s} {a['hostname']:14s} {str(a['composite_risk_score']):12s} {a['risk_severity']:10s} {str(m['max_cvss']):10s} {str(m['exposure_factor']):10s}")

    # Top risk should be D002 (Web Server) due to public exposure + 9.8 CVE
    assert assessments[0]["node_id"] == "D002", f"Expected D002 to be highest risk, got {assessments[0]['node_id']}"
    print(f"\n[+] Verified: {assessments[0]['node_id']} flagged as primary risk asset ({assessments[0]['composite_risk_score']} - {assessments[0]['risk_severity']}).")

    # 2. Threat Escalation Test: Simulate active reconnaissance scan (Threat prob = 0.8)
    print("\n[+] Simulating Active Threat Escalation (Threat Probability: 0.2 -> 0.8)...")
    escalated = risk_engine.calculate_node_risk(twin_engine.node_registry["D002"], threat_probability=0.8)
    print(f"    D002 Escalated Risk Score: {escalated['composite_risk_score']} ({escalated['risk_severity']})")
    assert escalated["risk_severity"] == "CRITICAL", "D002 should enter CRITICAL severity under active threat"

    print("\n[+] Risk Engine equations and severity transitions verified successfully.")

if __name__ == "__main__":
    run_risk_audit()