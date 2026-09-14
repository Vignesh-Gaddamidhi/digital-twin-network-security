import sys
import json
import math
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.calculation.core_risk_calculator import core_risk_calculator

def run_day130_suite():
    print("=" * 80)
    print("       WEEK 19 - DAY 130: CORE RISK CALCULATION ENGINE AUDIT")
    print("=" * 80 + "\n")

    core_risk_calculator.clear()

    # 1. Canonical Specification Test: 0.87 * 1.0 * 0.8 * 1.0 = 0.696 -> 69.6 (HIGH)
    print("[1/6] Auditing Canonical Multiplicative Risk Example (0.87 * 1.0 * 0.8 * 1.0)...")
    res_canon = core_risk_calculator.compute_risk(
        prediction_id="PRED-CANON-130",
        device_id="DB-01",
        threat_probability=0.87,
        asset_criticality=1.00,
        vulnerability_score=0.80,
        attack_impact_score=1.00,
        asset_criticality_level="CRITICAL",
        vulnerability_level="HIGH",
        attack_impact_level="CRITICAL"
    )

    print(f"    Raw Risk Score     : {res_canon.rawRiskScore:.6f} (Expected: 0.696000)")
    print(f"    Display Risk Score : {res_canon.riskScore:.2f} / 100.0 (Expected: 69.60)")
    print(f"    Assigned Risk Tier : {res_canon.riskLevel.value} (Expected: HIGH)")
    print(f"    Formula Proof      : {res_canon.formulaProof}")

    assert abs(res_canon.rawRiskScore - 0.696000) < 1e-5
    assert abs(res_canon.riskScore - 69.60) < 1e-2
    assert res_canon.riskLevel == RiskLevelTier.HIGH
    print("    [PASS] Canonical multiplicative risk calculation verified.")

    # 2. Manual Test Case 1: T=0.5, A=0.4, V=0.4, I=0.4 -> 0.032 -> 3.20 (LOW)
    print("\n[2/6] Auditing Manual Test Case 1: T=0.5, A=0.4, V=0.4, I=0.4 -> 3.20 (LOW)...")
    tc1 = core_risk_calculator.compute_risk("PRED-TC1", "DEV-01", 0.5, 0.4, 0.4, 0.4)
    print(f"    Raw: {tc1.rawRiskScore:.6f} | Score: {tc1.riskScore:.2f} | Tier: {tc1.riskLevel.value}")
    assert abs(tc1.rawRiskScore - 0.032000) < 1e-5
    assert abs(tc1.riskScore - 3.20) < 1e-2
    assert tc1.riskLevel == RiskLevelTier.LOW
    print("    [PASS] Test Case 1 matched exact expected values.")

    # 3. Manual Test Case 2: T=0.8, A=0.8, V=0.8, I=0.8 -> 0.4096 -> 40.96 (MEDIUM)
    print("\n[3/6] Auditing Manual Test Case 2: T=0.8, A=0.8, V=0.8, I=0.8 -> 40.96 (MEDIUM)...")
    tc2 = core_risk_calculator.compute_risk("PRED-TC2", "DEV-02", 0.8, 0.8, 0.8, 0.8)
    print(f"    Raw: {tc2.rawRiskScore:.6f} | Score: {tc2.riskScore:.2f} | Tier: {tc2.riskLevel.value}")
    assert abs(tc2.rawRiskScore - 0.409600) < 1e-5
    assert abs(tc2.riskScore - 40.96) < 1e-2
    assert tc2.riskLevel == RiskLevelTier.MEDIUM
    print("    [PASS] Test Case 2 matched exact expected values.")

    # 4. Manual Test Case 3: T=0.9, A=1.0, V=1.0, I=1.0 -> 0.9000 -> 90.00 (CRITICAL)
    print("\n[4/6] Auditing Manual Test Case 3: T=0.9, A=1.0, V=1.0, I=1.0 -> 90.00 (CRITICAL)...")
    tc3 = core_risk_calculator.compute_risk("PRED-TC3", "DEV-03", 0.9, 1.0, 1.0, 1.0)
    print(f"    Raw: {tc3.rawRiskScore:.6f} | Score: {tc3.riskScore:.2f} | Tier: {tc3.riskLevel.value}")
    assert abs(tc3.rawRiskScore - 0.900000) < 1e-5
    assert abs(tc3.riskScore - 90.00) < 1e-2
    assert tc3.riskLevel == RiskLevelTier.CRITICAL
    print("    [PASS] Test Case 3 matched exact expected values.")

    # 5. Risk Contribution & Lineage Verification
    print("\n[5/6] Auditing Contributing Factors & Configuration Version Lineage...")
    print(f"    Contributing Factors: {res_canon.contributingFactors}")
    print(f"    Risk Engine Version : {res_canon.riskEngineVersion}")
    print(f"    Threshold Version   : {res_canon.thresholdConfigVersion}")

    assert res_canon.contributingFactors["threatProbability"] == "87.0%"
    assert res_canon.contributingFactors["assetCriticality"] == "CRITICAL"
    assert res_canon.contributingFactors["vulnerability"] == "HIGH"
    assert res_canon.contributingFactors["attackImpact"] == "CRITICAL"
    assert res_canon.riskEngineVersion == "v3.0-multiplicative"
    print("    [PASS] Factor contributions and configuration lineage verified.")

    # 6. Defensive Failure Handling (Reject missing/invalid inputs without arbitrary substitution)
    print("\n[6/6] Auditing Defensive Failure Handlers...")
    faults = [
        ("Missing Prediction ID", lambda: core_risk_calculator.compute_risk("", "DEV", 0.5, 0.5, 0.5, 0.5)),
        ("Missing Device ID", lambda: core_risk_calculator.compute_risk("P1", "", 0.5, 0.5, 0.5, 0.5)),
        ("Null Threat Probability", lambda: core_risk_calculator.compute_risk("P1", "D1", None, 0.5, 0.5, 0.5)),
        ("Negative Factor", lambda: core_risk_calculator.compute_risk("P1", "D1", -0.1, 0.5, 0.5, 0.5)),
        ("Out-of-Range Factor (>1.0)", lambda: core_risk_calculator.compute_risk("P1", "D1", 0.5, 1.2, 0.5, 0.5)),
        ("NaN Factor", lambda: core_risk_calculator.compute_risk("P1", "D1", 0.5, 0.5, float("nan"), 0.5)),
        ("Infinity Factor", lambda: core_risk_calculator.compute_risk("P1", "D1", 0.5, 0.5, 0.5, float("inf")))
    ]

    for label, fn in faults:
        rejected = False
        try:
            fn()
        except ValueError as e:
            rejected = True
            print(f"    {label:<28} -> Trapped: {e}")
        assert rejected, f"Failed to reject: {label}"

    # Verify Disk Artifact Persistence
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "risk_calculations.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 4
    assert stored[-1]["predictionId"] == "PRED-TC3"
    print("    [PASS] Defensive failure handling and disk persistence verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 130 CORE RISK CALCULATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day130_suite()