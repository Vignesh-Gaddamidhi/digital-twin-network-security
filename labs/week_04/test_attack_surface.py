import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.risk_engine import risk_engine

def run_attack_surface_audit():
    print("================================================================================")
    print("      WEEK 4 - DAY 26: VULNERABILITY LIFECYCLE & ATTACK SURFACE AUDIT           ")
    print("================================================================================\n")

    # Bootstrap
    bootstrap_security_grounding()

    print("[1/3] Auditing Device Digital Attack Surfaces & Exposure Tiers...")
    for dev_id, dev in twin_engine.node_registry.items():
        surf = dev.attack_surface
        print(f"  Device [{dev.id}] {dev.hostname:14s} | Tier: {surf.exposure_tier:10s} | Access: {surf.accessibility:10s} | Ingress Ports: {surf.ingress_port_count:2d} | Open CVEs: {surf.open_vulnerability_count:2d}")
    
    assert twin_engine.node_registry["D004"].attack_surface.exposure_tier == "EXTERNAL"
    assert twin_engine.node_registry["D002"].attack_surface.exposure_tier == "DMZ"
    assert twin_engine.node_registry["D001"].attack_surface.exposure_tier == "INTERNAL"

    # Step 2: Evaluate Initial Baseline Risk
    print("\n[2/3] Evaluating Initial Baseline Risk Across Assets (Threat Prob = 0.2)...")
    assessments = risk_engine.evaluate_entire_topology(ambient_threat_prob=0.2)
    initial_d002_risk = next(a for a in assessments if a["node_id"] == "D002")
    print(f"  D002 Initial Risk: {initial_d002_risk['composite_risk_score']} ({initial_d002_risk['risk_severity']})")
    assert initial_d002_risk["risk_severity"] in ("MEDIUM", "HIGH")

    # Step 3: Transition Vulnerability Lifecycle from OPEN -> PATCHED
    print("\n[3/3] Simulating Vulnerability Remediation (VULN-D002-01: OPEN -> PATCHED)...")
    updated = twin_engine.update_vulnerability_status(
        node_id="D002",
        vuln_id="VULN-D002-01",
        new_status="PATCHED"
    )
    assert updated, "Failed to update vulnerability status"

    # Re-evaluate Risk
    post_patch_risk = risk_engine.calculate_node_risk(twin_engine.node_registry["D002"], threat_probability=0.2)
    print(f"  D002 Post-Patch Risk Score: {post_patch_risk['composite_risk_score']} ({post_patch_risk['risk_severity']})")
    print(f"  Open CVEs Remaining Count : {post_patch_risk['metrics']['open_vulns_count']}")
    print(f"  Max CVSS Evaluated        : {post_patch_risk['metrics']['max_cvss']}")

    assert post_patch_risk["composite_risk_score"] < initial_d002_risk["composite_risk_score"], "Risk score should drop significantly after patching!"
    assert post_patch_risk["risk_severity"] == "LOW", "D002 should drop to LOW severity after patching primary RCE CVE"

    print("\n================================================================================")
    print("      ATTACK SURFACE & VULNERABILITY LIFECYCLE AUDIT PASSED SUCCESSFULLY        ")
    print("================================================================================")

if __name__ == "__main__":
    run_attack_surface_audit()