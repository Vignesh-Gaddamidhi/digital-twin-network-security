import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine

def run_state_machine_audit():
    print("================================================================================")
    print("       WEEK 4 - DAY 25: DYNAMIC DEVICE STATE & FSM TRANSITION AUDIT             ")
    print("================================================================================\n")

    # Bootstrap baseline
    bootstrap_security_grounding()
    web_server = twin_engine.node_registry["D002"]

    print("[1/4] Auditing Dual-Track Decoupling on D002 (Web Server)...")
    print(f"  Operational Health: {web_server.current_state.status} | CPU: {web_server.current_state.cpu_usage_pct}% | RAM: {web_server.current_state.memory_usage_pct}%")
    print(f"  Security Status   : {web_server.security_state_model.security_status} (Risk: {web_server.security_state_model.risk_score})\n")

    assert web_server.current_state.status == "ONLINE"
    assert web_server.security_state_model.security_status == "NORMAL"

    # Step 1: Simulate Operational Traffic Spike (Operational Health Changes, Security Stays Normal)
    print("[2/4] Updating Operational Health Metrics (Under Heavy Web Ingress Traffic)...")
    twin_engine.update_current_operational_state(
        node_id="D002",
        cpu_pct=78.5,
        mem_pct=64.2,
        pps=450.0,
        bps=3500000.0,
        status="ONLINE"
    )
    updated_op = twin_engine.node_registry["D002"].current_state
    print(f"  New Operational Metrics: CPU={updated_op.cpu_usage_pct}% | PPS={updated_op.network_state.packet_rate_pps} | Status={updated_op.status}")
    print(f"  Security State Remains : {twin_engine.node_registry['D002'].security_state_model.security_status}")
    assert updated_op.cpu_usage_pct == 78.5
    assert twin_engine.node_registry["D002"].security_state_model.security_status == "NORMAL"

    # Step 2: Progress Security FSM through Attack Degradation
    print("\n[3/4] Driving Security FSM Attack Degradation Lifecycle...")
    
    # Transition 1: Anomaly flags node as SUSPICIOUS
    rec1 = twin_engine.transition_security_state(
        node_id="D002",
        new_state="SUSPICIOUS",
        trigger_source="NETWORK_ANOMALY_DETECTOR",
        reason="Port reconnaissance scan probe against port 4444"
    )
    print(f"  Transition 1: {rec1.previous_state} -> {rec1.new_state} (Trigger: {rec1.trigger_source})")

    # Transition 2: RCE Exploit compromises host
    rec2 = twin_engine.transition_security_state(
        node_id="D002",
        new_state="COMPROMISED",
        trigger_source="SURICATA_NIDS",
        reason="Exploit shellcode execution matching CVE-2023-38408"
    )
    print(f"  Transition 2: {rec2.previous_state} -> {rec2.new_state} (Trigger: {rec2.trigger_source})")

    # Transition 3: Containment quarantines host
    rec3 = twin_engine.transition_security_state(
        node_id="D002",
        new_state="ISOLATED",
        trigger_source="AUTOMATED_CONTAINMENT_POLICY",
        reason="Compromised asset severed from core switch fabric"
    )
    print(f"  Transition 3: {rec3.previous_state} -> {rec3.new_state} (Trigger: {rec3.trigger_source})")

    # Step 3: Progress Security FSM through Recovery Workflow
    print("\n[4/4] Driving Security FSM Remediation & Recovery Lifecycle...")
    
    # Transition 4: Patching and process termination
    rec4 = twin_engine.transition_security_state(
        node_id="D002",
        new_state="REMEDIATED",
        trigger_source="SOC_SECURITY_ENGINEER",
        reason="Terminated rogue shell process and applied OpenSSH patch 9.3p2"
    )
    print(f"  Transition 4: {rec4.previous_state} -> {rec4.new_state} (Trigger: {rec4.trigger_source})")

    # Transition 5: Return to normal baseline
    rec5 = twin_engine.transition_security_state(
        node_id="D002",
        new_state="NORMAL",
        trigger_source="POLICY_VALIDATION_SUITE",
        reason="Re-attached to production VLAN; 300s telemetry baseline verified"
    )
    print(f"  Transition 5: {rec5.previous_state} -> {rec5.new_state} (Trigger: {rec5.trigger_source})")

    # Validate History Log
    history = twin_engine.state_history
    print(f"\n[*] Immutable Audit Trail Records Count: {len(history)}")
    for h in history:
        print(f"  [{h.timestamp[11:19]}] {h.device_id:5s} | {h.previous_state:11s} -> {h.new_state:11s} | Source: {h.trigger_source:28s} | {h.reason}")

    assert len(history) == 5, f"Expected 5 history records, got {len(history)}"
    assert history[0].previous_state == "NORMAL" and history[0].new_state == "SUSPICIOUS"
    assert history[-1].new_state == "NORMAL"

    print("\n================================================================================")
    print("      DYNAMIC DEVICE STATE & FSM TRANSITION AUDIT PASSED SUCCESSFULLY           ")
    print("================================================================================")

if __name__ == "__main__":
    run_state_machine_audit()