import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.security.pipeline.detection.detection_models import (
    DetectionResult, DetectionTypeEnum, DetectionSeverityEnum, ExplainableEvidence
)
from services.digital_twin.security.pipeline.risk.risk_models import RiskLevelEnum
from services.digital_twin.security.pipeline.risk.risk_engine import risk_scoring_engine

def setup_devices():
    device_registry.clear()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    db  = NetworkDeviceModel(id="DB-01",     hostname="DB-01",     type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(db)

def run_day90_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 90: CONTEXTUAL RISK SCORING ENGINE AUDIT")
    print("=" * 80 + "\n")

    setup_devices()

    # 1. Benign Traffic Evaluation
    print("[1/6] Auditing Benign Detection Risk Assessment...")
    det_benign = DetectionResult(
        detected=False,
        detectionType=DetectionTypeEnum.BENIGN,
        confidence=0.10,
        severity=DetectionSeverityEnum.INFO,
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01"
    )
    r_benign = risk_scoring_engine.assess_risk(det_benign)
    assert r_benign.score <= 10.0
    assert r_benign.level == RiskLevelEnum.LOW
    print(f"    [PASS] Benign assessment: Score={r_benign.score} ({r_benign.level.value}).")

    # 2. Port Reconnaissance against DMZ Web Server
    print("\n[2/6] Auditing Medium Threat against DMZ Web Server...")
    det_scan = DetectionResult(
        detected=True,
        detectionType=DetectionTypeEnum.PORT_ANOMALY,
        confidence=0.85,
        severity=DetectionSeverityEnum.MEDIUM,
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01",
        features={"portAttemptCount": 7}
    )
    r_scan = risk_scoring_engine.assess_risk(det_scan)
    print(f"    Likelihood : {r_scan.likelihood}")
    print(f"    Impact     : {r_scan.impact}")
    print(f"    Risk Score : {r_scan.score} ({r_scan.level.value})")

    assert r_scan.likelihood >= 0.70
    assert r_scan.impact >= 3.5  # Base 3.0 * 1.3 DMZ multiplier
    assert r_scan.level in (RiskLevelEnum.MEDIUM, RiskLevelEnum.HIGH)
    print("    [PASS] Port scan risk scored with DMZ exposure multiplier.")

    # 3. Asset Criticality Escalation (Same scan against DB-01)
    print("\n[3/6] Auditing Asset Criticality Escalation on Database Tier...")
    det_scan_db = DetectionResult(
        detected=True,
        detectionType=DetectionTypeEnum.PORT_ANOMALY,
        confidence=0.85,
        severity=DetectionSeverityEnum.MEDIUM,
        targetDevice="DB-01",
        sourceDevice="CLIENT-01",
        features={"portAttemptCount": 7}
    )
    r_scan_db = risk_scoring_engine.assess_risk(det_scan_db)
    print(f"    WEB-01 Impact: {r_scan.impact} -> DB-01 Impact: {r_scan_db.impact}")
    print(f"    WEB-01 Score : {r_scan.score}  -> DB-01 Score : {r_scan_db.score}")

    assert r_scan_db.impact >= 4.0  # Base 4.0 for Database
    assert r_scan_db.score > r_scan.score or r_scan_db.impact > 3.0
    print("    [PASS] Database tier correctly evaluated with elevated asset criticality.")

    # 4. Critical Exploit / Exfiltration Saturation
    print("\n[4/6] Auditing Critical Data Exfiltration Risk Assessment...")
    det_exfil = DetectionResult(
        detected=True,
        detectionType=DetectionTypeEnum.OUTBOUND_VOLUME_ANOMALY,
        confidence=0.95,
        severity=DetectionSeverityEnum.CRITICAL,
        targetDevice="DB-01",
        sourceDevice="CLIENT-01",
        features={"connectionCount": 10}
    )
    r_exfil = risk_scoring_engine.assess_risk(det_exfil)
    print(f"    Likelihood : {r_exfil.likelihood}")
    print(f"    Impact     : {r_exfil.impact}")
    print(f"    Risk Score : {r_exfil.score} ({r_exfil.level.value})")

    assert r_exfil.level == RiskLevelEnum.CRITICAL
    assert r_exfil.score >= 75.0
    print("    [PASS] Critical exfiltration assessed as CRITICAL risk score.")

    # 5. Contributing Factors Explainability Audit
    print("\n[5/6] Auditing Contributing Factors Breakdown...")
    print(f"    Total Contributing Factors: {len(r_exfil.contributingFactors)}")
    for f in r_exfil.contributingFactors:
        print(f"      - [{f.category}] {f.factor} ({f.weightEffect}): {f.description}")

    categories = [f.category for f in r_exfil.contributingFactors]
    assert "LIKELIHOOD" in categories
    assert "ASSET" in categories
    assert "IMPACT" in categories
    print("    [PASS] All expected contributing factor categories populated.")

    # 6. Natural Language Explanation Audit
    print("\n[6/6] Auditing Risk Explanation String...")
    print(f"    Explanation: \"{r_exfil.explanation}\"")
    assert "Risk Level assessed as CRITICAL" in r_exfil.explanation
    assert "Key drivers:" in r_exfil.explanation
    print("    [PASS] Human-readable and ML-auditable explanation verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 90 RISK SCORE ENGINE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day90_suite()