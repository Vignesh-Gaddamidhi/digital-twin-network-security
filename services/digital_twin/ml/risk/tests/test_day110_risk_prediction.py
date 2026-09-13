import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.risk.risk_models import (
    DeviceCriticalityEnum, NetworkExposureEnum, VulnerabilityStatusEnum,
    OperationalRiskLevel, RiskThresholdConfig
)
from services.digital_twin.ml.risk.prediction_risk_engine import prediction_risk_engine

def run_day110_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 110: CONTEXTUAL RISK PREDICTION AUDIT")
    print("=" * 80 + "\n")

    prediction_risk_engine.clear()

    # 1. Verification of Invariant: Risk != Probability Alone
    print("[1/5] Auditing Invariant: Threat Probability != Risk Level...")
    # Scenario A: 90% threat on an isolated non-critical workstation with zero vulnerabilities
    risk_isolated = prediction_risk_engine.assess_risk(
        prediction_id="PRED-TEST-A",
        threat_probability=0.90,
        predicted_category="PORT_SCAN",
        category_confidence=0.85,
        device_criticality=DeviceCriticalityEnum.LOW,
        network_exposure=NetworkExposureEnum.INTERNAL_ISOLATED,
        vulnerability_status=VulnerabilityStatusEnum.NONE_KNOWN
    )

    # Scenario B: 90% threat on an external mission-critical server with an open unpatched CVE
    risk_exposed = prediction_risk_engine.assess_risk(
        prediction_id="PRED-TEST-B",
        threat_probability=0.90,
        predicted_category="PORT_SCAN",
        category_confidence=0.85,
        device_criticality=DeviceCriticalityEnum.MISSION_CRITICAL,
        network_exposure=NetworkExposureEnum.EXTERNAL_FACING,
        vulnerability_status=VulnerabilityStatusEnum.OPEN_UNPATCHED
    )

    print(f"    Scenario A (Low Asset)     : Threat Prob=90% -> Score={risk_isolated.riskScore} -> Level={risk_isolated.riskLevel.value}")
    print(f"    Scenario B (Critical Asset): Threat Prob=90% -> Score={risk_exposed.riskScore} -> Level={risk_exposed.riskLevel.value}")

    assert risk_isolated.riskLevel in (OperationalRiskLevel.LOW, OperationalRiskLevel.MEDIUM)
    assert risk_exposed.riskLevel in (OperationalRiskLevel.HIGH, OperationalRiskLevel.CRITICAL)
    assert risk_isolated.riskScore < risk_exposed.riskScore
    print("    [PASS] Risk level appropriately differentiates based on asset context.")

    # 2. Canonical Example Verification (87% Threat, 91% Conf, External, Open Vuln)
    print("\n[2/5] Auditing Canonical Week 16 Specification Example...")
    canonical_risk = prediction_risk_engine.assess_risk(
        prediction_id="PRED-CANONICAL-01",
        threat_probability=0.87,
        predicted_category="NETWORK_INTRUSION",
        category_confidence=0.91,
        device_criticality=DeviceCriticalityEnum.HIGH,
        network_exposure=NetworkExposureEnum.EXTERNAL_FACING,
        vulnerability_status=VulnerabilityStatusEnum.OPEN_UNPATCHED,
        observed_anomalies=["Abnormal connection behavior"]
    )

    print(f"    Calculated Risk Score : {canonical_risk.riskScore}")
    print(f"    Calculated Risk Level : {canonical_risk.riskLevel.value}")
    assert canonical_risk.riskLevel in (OperationalRiskLevel.HIGH, OperationalRiskLevel.CRITICAL)
    assert canonical_risk.riskScore >= 60.0
    print("    [PASS] Canonical test produced expected elevated operational risk level.")

    # 3. Explainability and Contributing Factors Audit
    print("\n[3/5] Auditing Contributing Factors & Human-Readable Explanation...")
    factors = canonical_risk.contributingFactors
    print("    Contributing Factors:")
    for f in factors:
        print(f"      * {f}")
    print(f"    Summary Display:\n{canonical_risk.to_summary_string()}")

    assert any("Elevated threat probability" in f for f in factors)
    assert any("Heightened asset exposure" in f for f in factors)
    assert any("open unpatched vulnerability" in f.lower() for f in factors)
    assert "Abnormal connection behavior" in factors
    print("    [PASS] Full causal explainability captured.")

    # 4. Configurable Threshold Boundaries Audit
    print("\n[4/5] Auditing Configurable Severity Thresholds...")
    strict_cfg = RiskThresholdConfig(lowThreshold=15.0, mediumThreshold=40.0, highThreshold=65.0)
    strict_engine = prediction_risk_engine.__class__(thresholds=strict_cfg)

    strict_assessment = strict_engine.assess_risk(
        prediction_id="PRED-STRICT",
        threat_probability=0.60,
        predicted_category="PORT_SCAN",
        category_confidence=0.70,
        device_criticality=DeviceCriticalityEnum.MEDIUM,
        network_exposure=NetworkExposureEnum.INTERNAL_ROUTABLE,
        vulnerability_status=VulnerabilityStatusEnum.PATCHED
    )
    print(f"    Risk Score under strict thresholds: {strict_assessment.riskScore} -> {strict_assessment.riskLevel.value}")
    assert strict_assessment.riskLevel in (OperationalRiskLevel.MEDIUM, OperationalRiskLevel.HIGH)
    print("    [PASS] Dynamic threshold configuration validated.")

    # 5. Persistent Artifact Verification
    print("\n[5/5] Auditing Artifact Persistence to Disk...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk" / "risk_assessments.json"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        stored_data = json.load(f)
    assert len(stored_data) >= 3
    print(f"    Persisted Assessments Count: {len(stored_data)}")
    print("    [PASS] Assessments verified in risk_assessments.json.")

    print("\n" + "=" * 80)
    print("       ALL DAY 110 RISK PREDICTION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day100_suite = run_day110_suite
    run_day110_suite()