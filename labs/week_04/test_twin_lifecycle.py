import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_04.twin_core_prototype import LivingDigitalTwinCore

def run_lifecycle_test():
    print("================================================================================")
    print("       WEEK 4 - DAY 22: DIGITAL TWIN OPERATIONAL LIFECYCLE AUDIT                ")
    print("================================================================================\n")

    # 1. DISCOVER, CREATE, INITIALIZE
    print("[1/5] Bootstrapping Living Digital Twin Core (Stages 1-3)...")
    twin = LivingDigitalTwinCore()
    state = twin.get_canonical_state()
    print(f"    [+] Initialized Topology: {len(state['devices'])} devices, {len(state['links'])} links.")
    print(f"    [+] Lifecycle Stage: {twin.lifecycle_stage}\n")
    assert len(state["devices"]) == 5, "Expected 5 canonical devices (D001-D005)"

    # 2. SYNC & UPDATE
    print("[2/5] Ingesting Live Telemetry to Synchronize State (Stages 4-6)...")
    sync_res = twin.sync_telemetry_event(
        source_ip="192.168.1.99",
        dest_ip="192.168.1.10",
        dest_port=22,
        flags="S"
    )
    print(f"    [+] Synchronized Node  : {sync_res['synchronized_node']}")
    print(f"    [+] Security State     : {sync_res['current_security_state']}")
    print(f"    [+] Updated CIA Posture: {sync_res['cia']}\n")
    assert sync_res["current_security_state"] == "SUSPICIOUS"

    # 3. SIMULATE (Branching State)
    print("[3/5] Forking Twin State for Speculative Simulation (Stage 7)...")
    branch = twin.fork_simulation(branch_id="SIM-ATTACK-BURST-01")
    print(f"    [+] Live Twin Stage   : {twin.lifecycle_stage}")
    print(f"    [+] Forked Branch Stage: {branch.lifecycle_stage}")
    assert branch.lifecycle_stage == "SIMULATE"

    # 4. PREDICT (Attack Path Forecasting)
    print("\n[4/5] Executing Predictive Lateral Movement Forecast (Stage 8)...")
    prediction = twin.predict_next_attack_target(origin_node_id="D002")
    forecast = prediction["forecasted_next_target"]
    print(f"    [+] Compromised Origin   : {prediction['origin_compromised_node']}")
    print(f"    [+] Predicted Next Target: {forecast['hostname']} ({forecast['target_node_id']})")
    print(f"    [+] Transition Likelihood: {forecast['lateral_pivot_probability'] * 100:.1f}%\n")
    assert forecast is not None
    # Allowed targets are any peer node in the topology except origin D002
    assert forecast["target_node_id"] in ("D001", "D003", "D004", "D005"), f"Unexpected forecast target: {forecast['target_node_id']}"

    # 5. RESPOND (Containment Orchestration)
    print("[5/5] Triggering Automated Response & Isolation (Stage 9)...")
    response_res = twin.execute_containment_response(compromised_node_id="D002")
    print(f"    [+] Containment Action : {response_res['action']}")
    print(f"    [+] Target Node State  : {response_res['security_state']}")
    print(f"    [+] Severed Links Count: {response_res['severed_links_count']}")
    assert response_res["security_state"] == "ISOLATED"

    print("\n================================================================================")
    print("      DIGITAL TWIN CONCEPT SPECIFICATION & LIFECYCLE AUDIT PASSED               ")
    print("================================================================================")

if __name__ == "__main__":
    run_lifecycle_test()