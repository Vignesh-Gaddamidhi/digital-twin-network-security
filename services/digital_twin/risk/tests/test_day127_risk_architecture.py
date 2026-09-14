import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import (
    AssetCriticalityLevel, VulnerabilitySeverityLevel, AttackImpactLevel,
    RiskLevelTier, FACTOR_NORMALIZATION_MAP
)
from services.digital_twin.risk.validation.risk_schema import RiskAssessment
from services.digital_twin.risk.engine.risk_scoring_engine import risk_scoring_engine

def run_day127_suite():
    print("=" * 80)
    print("       WEEK 19 - DAY 127: RISK SCORING ARCHITECTURE & FACTOR AUDIT")
    print("=" * 80 + "\n")

    risk_scoring_engine.clear()

    # 1. All Four Factors Recognition & Normalization
    print("[1/6] Auditing All Four Required Factor Scales & Normalization Weights...")
    assert FACTOR_NORMALIZATION_MAP["VERY_LOW"] == 0.20
    assert FACTOR_NORMALIZATION_MAP["LOW"] == 0.40
    assert FACTOR_NORMALIZATION_MAP["MEDIUM"] == 0.60
    assert FACTOR_NORMALIZATION_MAP["HIGH"] == 0.80
    assert FACTOR_NORMALIZATION_MAP["CRITICAL"] == 1.00

    print("    Normalization Scale Verified: VERY_LOW=0.20 -> CRITICAL=1.00")
    print("    [PASS] All 4 factors present and normalized.")

    # 2. Mathematical Multiplicative Formulation (Canonical Specification Example)
    print("\n[2/6] Auditing Canonical Multiplicative Risk Calculation (0.87 * 1.0 * 0.8 * 1.0)...")
    # P=0.87, C=CRITICAL (1.0), V=HIGH (0.8), I=CRITICAL (1.0) -> Raw = 0.87 * 1.0 * 0.8 * 1.0 = 0.696
    res_canon = risk_scoring_engine.calculate_risk(
        prediction_id="PRED-CANON-127",
        device_id="CORE-DB-01",
        threat_probability=0.87,
        asset_criticality=AssetCriticalityLevel.CRITICAL,
        vulnerability_severity=VulnerabilitySeverityLevel.HIGH,
        attack_impact=AttackImpactLevel.CRITICAL,
        predicted_category="EXFILTRATION_LIKE"
    )

    print(f"    Calculated Raw Risk : {res_canon.rawRiskScore:.4f} (Expected: 0.6960)")
    print(f"    Calculated Score    : {res_canon.riskScore:.2f} / 100.0 (Expected: 69.60)")
    print(f"    Assigned Risk Level : {res_canon.riskLevel.value}")

    assert abs(res_canon.rawRiskScore - 0.6960) < 1e-3
    assert abs(res_canon.riskScore - 69.60) < 1e-1
    assert res_canon.riskLevel == RiskLevelTier.HIGH
    print("    [PASS] Multiplicative formula exact numerical precision verified.")

    # 3. Threat vs. Risk Decoupling Audit (Device A vs Device B)
    print("\n[3/6] Auditing Threat vs. Risk Decoupling (Device A vs Device B)...")
    # Device A: Unimportant client workstation (P=0.90, C=LOW, V=LOW, I=LOW)
    # Raw = 0.90 * 0.4 * 0.4 * 0.4 = 0.0576 (Score: 5.76) -> LOW risk
    dev_a = risk_scoring_engine.calculate_risk(
        prediction_id="PRED-DEV-A",
        device_id="CLIENT-01",
        threat_probability=0.90,
        asset_criticality=AssetCriticalityLevel.LOW,
        vulnerability_severity=VulnerabilitySeverityLevel.LOW,
        attack_impact=AttackImpactLevel.LOW,
        predicted_category="PORT_SCAN"
    )

    # Device B: Mission-critical server (P=0.90, C=CRITICAL, V=HIGH, I=CRITICAL)
    # Raw = 0.90 * 1.0 * 0.8 * 1.0 = 0.7200 (Score: 72.00) -> CRITICAL risk
    dev_b = risk_scoring_engine.calculate_risk(
        prediction_id="PRED-DEV-B",
        device_id="PROD-DB-01",
        threat_probability=0.90,
        asset_criticality=AssetCriticalityLevel.CRITICAL,
        vulnerability_severity=VulnerabilitySeverityLevel.HIGH,
        attack_impact=AttackImpactLevel.CRITICAL,
        predicted_category="EXFILTRATION_LIKE"
    )

    print(f"    Device A (Client WS) : Threat Prob={dev_a.threatProbability*100:.0f}% -> Risk Score={dev_a.riskScore:.2f} ({dev_a.riskLevel.value})")
    print(f"    Device B (Core DB)   : Threat Prob={dev_b.threatProbability*100:.0f}% -> Risk Score={dev_b.riskScore:.2f} ({dev_b.riskLevel.value})")

    assert dev_a.threatProbability == dev_b.threatProbability
    assert dev_a.riskLevel == RiskLevelTier.LOW
    assert dev_b.riskLevel == RiskLevelTier.CRITICAL
    assert dev_b.riskScore > (dev_a.riskScore * 10)
    print("    [PASS] Threat != Risk proven: Identical probability produces distinct contextual risk.")

    # 4. RiskAssessment Schema Validation & Formatted Card Display
    print("\n[4/6] Auditing RiskAssessment Card Serialization...")
    card_str = res_canon.to_formatted_card()
    print(card_str)
    assert "RISK ASSESSMENT CARD" in card_str
    assert "0.87 × 1.00 × 0.80 × 1.00" in card_str
    assert "69.60" in card_str
    print("    [PASS] RiskAssessment visual card validated.")

    # 5. Defensive Rejection of Out-of-Bounds Threat Probabilities
    print("\n[5/6] Auditing Defensive Rejection of Invalid Threat Probabilities...")
    upper_bound_caught = False
    try:
        risk_scoring_engine.calculate_risk(
            prediction_id="ERR-01", device_id="TEST", threat_probability=1.5,
            asset_criticality=AssetCriticalityLevel.HIGH,
            vulnerability_severity=VulnerabilitySeverityLevel.LOW,
            attack_impact=AttackImpactLevel.LOW
        )
    except ValueError:
        upper_bound_caught = True
    assert upper_bound_caught, "Engine failed to reject threat probability > 1.0"

    lower_bound_caught = False
    try:
        risk_scoring_engine.calculate_risk(
            prediction_id="ERR-02", device_id="TEST", threat_probability=-0.2,
            asset_criticality=AssetCriticalityLevel.HIGH,
            vulnerability_severity=VulnerabilitySeverityLevel.LOW,
            attack_impact=AttackImpactLevel.LOW
        )
    except ValueError:
        lower_bound_caught = True
    assert lower_bound_caught, "Engine failed to reject threat probability < 0.0"

    print("    [PASS] Invalid threat probabilities safely trapped and rejected.")

    # 6. Disk Persistence Verification
    print("\n[6/6] Auditing Risk Assessment Persistence to Disk...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "risk_assessments.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 3
    assert stored[-1]["riskEngineVersion"] == "v3.0-multiplicative"
    print(f"    Persisted Assessments Count: {len(stored)}")
    print("    [PASS] Risk assessments persisted and validated on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 127 RISK SCORING ARCHITECTURE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day127_suite()