import sys
import json
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import (
    VulnerabilitySeverityLevel, RiskLevelTier
)
from services.digital_twin.risk.factors.vulnerability.vulnerability_engine import (
    VulnerabilityRecord, VulnerabilityStatus
)
from services.digital_twin.risk.engine.master_risk_orchestrator import master_risk_orchestrator

def run_day133_suite():
    print("=" * 80)
    print("       WEEK 19 - DAY 133: END-TO-END RISK VALIDATION & PHASE 16 MILESTONE")
    print("=" * 80 + "\n")

    master_risk_orchestrator.clear()

    # 1. Canonical Specification Test Case: DB-01 under PORT_SCAN
    print("[1/6] Auditing Canonical Final Risk Object (DB-01, P=0.87, C=1.0, V=0.8, I=1.0)...")
    db_vulns = [
        VulnerabilityRecord(
            vulnerabilityId="CVE-2026-SQLI",
            name="Unauthenticated SQL Injection",
            severity=VulnerabilitySeverityLevel.HIGH,
            status=VulnerabilityStatus.OPEN,
            affectedService="MYSQL"
        )
    ]
    top_features = ["connection_frequency", "destination_diversity", "unique_destination_ports", "failed_connections"]

    from services.digital_twin.risk.factors.factor_types import AttackImpactLevel
    res_canon = master_risk_orchestrator.process_end_to_end_risk(
        prediction_id="PRED-000123",
        device_id="DB-01",
        threat_probability=0.87,
        predicted_category="PORT_SCAN",
        category_confidence=0.91,
        top_contributing_features=top_features,
        custom_vulnerabilities=db_vulns,
        target_service="MYSQL",
        custom_attack_impact=AttackImpactLevel.CRITICAL
    )

    print(f"    Risk ID             : {res_canon.riskId}")
    print(f"    Target Device       : {res_canon.deviceId}")
    print(f"    Threat Probability  : {res_canon.threatProbability}")
    print(f"    Asset Criticality   : {res_canon.assetCriticality['level']} ({res_canon.assetCriticality['score']:.2f})")
    print(f"    Vulnerability       : {res_canon.vulnerability['level']} ({res_canon.vulnerability['score']:.2f}, {res_canon.vulnerability['status']})")
    print(f"    Attack Impact       : {res_canon.attackImpact['level']} ({res_canon.attackImpact['score']:.2f})")
    print(f"    Raw Risk Score      : {res_canon.rawRiskScore:.4f} (Expected: 0.6960)")
    print(f"    Operational Score   : {res_canon.riskScore:.2f} / 100.0 (Expected: 69.60)")
    print(f"    Risk Level          : {res_canon.riskLevel} (Expected: HIGH)")
    print(f"    Top Features Linked : {res_canon.topContributingFeatures}")
    print(f"    Explanation Status  : {res_canon.explanationStatus}")

    assert abs(res_canon.rawRiskScore - 0.6960) < 1e-3
    assert abs(res_canon.riskScore - 69.60) < 1e-1
    assert res_canon.riskLevel == RiskLevelTier.HIGH.value
    assert res_canon.predictedCategory == "PORT_SCAN"
    assert res_canon.status == "CALCULATED"
    assert res_canon.explanationStatus == "GENERATED"
    print("    [PASS] Canonical Final Risk Object verified with full schema compliance.")

    # 2. Complete Normal Scenario Evaluation (7 Protocols)
    print("\n[2/6] Auditing Normal Telemetry Scenarios across 7 Protocols (HTTP, HTTPS, DNS, SSH, ICMP, TCP, UDP)...")
    normal_protocols = ["HTTP", "HTTPS", "DNS", "SSH", "ICMP", "TCP", "UDP"]
    for proto in normal_protocols:
        res_norm = master_risk_orchestrator.process_end_to_end_risk(
            prediction_id=f"PRED-NORM-{proto}",
            device_id="CLIENT-01",
            threat_probability=0.08,
            predicted_category="NORMAL",
            category_confidence=0.98,
            target_service=proto
        )
        print(f"    Normal {proto:<6} -> Threat: {res_norm.threatProbability*100:.1f}% | Risk: {res_norm.riskScore:.2f} [{res_norm.riskLevel}]")
        assert res_norm.riskLevel == RiskLevelTier.LOW.value
        assert res_norm.riskScore < 25.0

    print("    [PASS] All 7 normal protocol streams assessed as LOW risk.")

    # 3. Complete Attack Scenario Evaluation (7 Canonical Profiles)
    print("\n[3/6] Auditing 7 Canonical Attack Scenarios on Targeted Topology Nodes...")
    attack_scenarios = [
        ("PORT_SCAN", "CLIENT-01", 0.75, ["connection_frequency", "destination_diversity"], None, RiskLevelTier.LOW.value),
        ("BRUTE_FORCE_LIKE", "WEB-01", 0.85, ["failed_connections", "connection_frequency"], "SSH", RiskLevelTier.MEDIUM.value),
        ("DOS_LIKE", "WEB-01", 0.95, ["packet_rate", "bytes_per_second"], "HTTP", RiskLevelTier.HIGH.value),
        ("DNS_ANOMALY", "DNS-SERVER-01", 0.80, ["dns_frequency", "dns_queries"], "DNS", RiskLevelTier.LOW.value),
        ("BEACONING", "CLIENT-01", 0.70, ["connection_frequency", "flow_duration"], "HTTPS", RiskLevelTier.LOW.value),
        ("LATERAL_MOVEMENT_LIKE", "WEB-01", 0.88, ["destination_diversity", "port_443_ratio"], "SMB", RiskLevelTier.HIGH.value),
        ("EXFILTRATION_LIKE", "DB-01", 0.95, ["bytes", "bytes_per_second"], "MYSQL", RiskLevelTier.CRITICAL.value)
    ]

    for cat, dev, prob, feats, srv, expected_min_tier in attack_scenarios:
        res_att = master_risk_orchestrator.process_end_to_end_risk(
            prediction_id=f"PRED-ATT-{cat}",
            device_id=dev,
            threat_probability=prob,
            predicted_category=cat,
            category_confidence=0.92,
            top_contributing_features=feats,
            target_service=srv
        )
        print(f"    Attack: {cat:<22} on {dev:<14} -> Threat: {prob*100:.0f}% | Score: {res_att.riskScore:5.2f} [{res_att.riskLevel}]")
        assert res_att.riskScore > 0.0

    print("    [PASS] All 7 attack scenarios successfully contextualized through risk engine.")

    # 4. Mandatory Failure Testing
    print("\n[4/6] Auditing Mandatory Failure Modes & Defensive Degradation Handlers...")
    # Test 4a: Missing threat probability
    caught_tp = False
    try:
        master_risk_orchestrator.process_end_to_end_risk("P1", "DB-01", None)
    except ValueError as e:
        caught_tp = "RISK_CALCULATION_FAILED" in str(e)
    assert caught_tp
    print("    Missing Threat Probability -> Trapped: RISK_CALCULATION_FAILED")

    # Test 4b: Unknown asset
    caught_asset = False
    try:
        master_risk_orchestrator.process_end_to_end_risk("P2", "UNKNOWN-HOST-99", 0.80)
    except KeyError as e:
        caught_asset = "ASSET_CONTEXT_UNAVAILABLE" in str(e)
    assert caught_asset
    print("    Unregistered Target Asset  -> Trapped: ASSET_CONTEXT_UNAVAILABLE")

    # Test 4c: Out of bounds factor
    caught_bounds = False
    try:
        master_risk_orchestrator.process_end_to_end_risk("P3", "DB-01", 1.80)
    except ValueError as e:
        caught_bounds = "INVALID_RISK_FACTOR" in str(e)
    assert caught_bounds
    print("    Out-of-Bounds Factor (1.80) -> Trapped: INVALID_RISK_FACTOR")

    # Test 4d: XAI unavailable (Graceful degradation to PARTIAL explanation)
    res_no_xai = master_risk_orchestrator.process_end_to_end_risk(
        prediction_id="P4",
        device_id="DB-01",
        threat_probability=0.85,
        predicted_category="PORT_SCAN",
        xai_explanation=None,
        top_contributing_features=None
    )
    assert res_no_xai.status == "CALCULATED"
    assert res_no_xai.explanationStatus == "PARTIAL"
    print("    XAI Unavailable            -> Degraded gracefully: status=CALCULATED, explanationStatus=PARTIAL")
    print("    [PASS] All mandatory failure modes and graceful degradations verified.")

    # 5. Pipeline Latency Profiling
    print("\n[5/6] Profiling Risk Engine Component Latency...")
    lat = res_canon.pipelineLatencyMs
    print(f"    Asset Lookup Latency       : {lat['assetLookupMs']} ms")
    print(f"    Vulnerability Resolution   : {lat['vulnerabilityResolutionMs']} ms")
    print(f"    Impact Evaluation          : {lat['impactEvaluationMs']} ms")
    print(f"    Core Multiplicative Calc   : {lat['coreCalculationMs']} ms")
    print(f"    Trend Evaluation           : {lat['trendEvaluationMs']} ms")
    print(f"    Explanation Synthesis      : {lat['explanationSynthesisMs']} ms")
    print(f"    Total Risk Pipeline Time   : {lat['totalPipelineLatencyMs']} ms")

    assert lat["totalPipelineLatencyMs"] < 50.0  # Real-time budget for workstation
    print("    [PASS] Risk calculation latency comfortably within real-time budget (<50 ms).")

    # 6. Audit Trail Persistence
    print("\n[6/6] Auditing Complete Audit Trail Persistence...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "final_risk_records.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        saved_records = json.load(f)
    assert len(saved_records) >= 10
    print(f"    Verified {len(saved_records)} persistent audit records in final_risk_records.json.")
    print("    [PASS] Audit log verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 133 END-TO-END RISK ENGINE TESTS PASSED CLEANLY")
    print("       PHASE 16: RISK SCORING ENGINE GRADUATED SUCCESSFULLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day133_suite()