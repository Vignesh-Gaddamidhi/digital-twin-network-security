import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.xai.evidence.unified_pipeline import unified_explainable_pipeline
from services.digital_twin.ml.risk.risk_models import (
    DeviceCriticalityEnum, NetworkExposureEnum, VulnerabilityStatusEnum
)

def run_day124_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 124: XAI + ATTACK CATEGORY + RISK + EARLY WARNING AUDIT")
    print("=" * 80 + "\n")

    unified_explainable_pipeline.clear()

    # 1. Normal Baseline Scenarios (5 Protocols)
    print("[1/5] Auditing Normal Baseline Telemetry Scenarios (HTTP, HTTPS, DNS, SSH, ICMP)...")
    normal_scenarios = [
        ("Normal HTTP", {"packet_rate": -0.8, "bytes": -0.7, "tcp_ratio": 0.8, "port_80_ratio": 1.0}),
        ("Normal HTTPS", {"packet_rate": -0.6, "bytes": -0.5, "tcp_ratio": 0.9, "port_443_ratio": 1.0}),
        ("Normal DNS", {"packet_rate": -0.9, "dns_queries": -0.7, "port_53_ratio": 1.0, "udp_ratio": 0.9}),
        ("Normal SSH", {"packet_rate": -0.8, "bytes": -0.8, "port_22_ratio": 1.0, "failed_connections": -0.5}),
        ("Normal ICMP", {"packet_rate": -0.9, "bytes": -0.9, "connection_frequency": -0.8})
    ]

    for label, feats in normal_scenarios:
        res = unified_explainable_pipeline.process_telemetry(
            features=feats,
            source="CLIENT-01",
            destination="GATEWAY-01",
            device_id="GATEWAY-01",
            device_criticality=DeviceCriticalityEnum.MEDIUM,
            network_exposure=NetworkExposureEnum.INTERNAL_ROUTABLE,
            vulnerability_status=VulnerabilityStatusEnum.NONE_KNOWN,
            current_stage="BASELINE"
        )
        print(f"    Scenario: {label:<14} -> Threat: {res['current']['threatProbability']:<6} | Cat: {res['current']['predictedCategory']:<8} | Risk: {res['current']['riskLevel']}")
        assert res["current"]["predictedCategory"] == "NORMAL"
        assert res["current"]["riskLevel"] in ("LOW", "MEDIUM")
        assert res["alert"] is None
        assert "normal" in res["xai"]["summary"].lower()

    print("    [PASS] All 5 normal scenarios classified as benign with zero alerts.")

    # 2. Suspicious Attack Scenarios (6 Canonical Profiles)
    print("\n[2/5] Auditing Suspicious Attack Scenarios (PORT_SCAN, DOS, DNS, BEACONING, LATERAL, EXFILTRATION)...")
    attack_scenarios = [
        (
            "PORT_SCAN",
            {"unique_destination_ports": 3.0, "port_other_ratio": 2.5, "failed_connections": 2.0, "connection_frequency": 2.8, "destination_diversity": 2.5},
            "PORT_SCAN",
            ["connection frequency", "destination", "port"]
        ),
        (
            "DOS_LIKE",
            {"packet_rate": 4.0, "bytes_per_second": 3.5, "flow_duration": -0.8, "bytes": 3.8},
            "DOS_LIKE",
            ["packet", "rate", "byte"]
        ),
        (
            "DNS_ANOMALY",
            {"dns_queries": 3.5, "dns_frequency": 3.5, "port_53_ratio": 3.0, "udp_ratio": 2.0},
            "DNS_ANOMALY",
            ["dns", "query"]
        ),
        (
            "BEACONING",
            {"connection_frequency": 2.0, "flow_duration": 2.5, "tcp_ratio": 1.0, "destination_diversity": -0.5},
            "BEACONING",
            ["connection frequency", "session", "flow"]
        ),
        (
            "LATERAL_MOVEMENT_LIKE",
            {"destination_diversity": 3.5, "unique_destination_ratio": 3.0, "port_443_ratio": 1.5},
            "LATERAL_MOVEMENT_LIKE",
            ["destination diversity", "endpoints"]
        ),
        (
            "EXFILTRATION_LIKE",
            {"bytes": 4.0, "bytes_per_second": 4.0, "flow_duration": 2.0},
            "EXFILTRATION_LIKE",
            ["byte", "volume", "bandwidth"]
        )
    ]

    for label, feats, expected_cat, expected_terms in attack_scenarios:
        res = unified_explainable_pipeline.process_telemetry(
            features=feats,
            source="ATTACKER-HOST",
            destination=f"VICTIM-{expected_cat}",
            device_id=f"VICTIM-{expected_cat}",
            device_criticality=DeviceCriticalityEnum.HIGH,
            network_exposure=NetworkExposureEnum.EXTERNAL_FACING,
            vulnerability_status=VulnerabilityStatusEnum.OPEN_UNPATCHED,
            current_stage="EARLY_INDICATORS"
        )
        print(f"\n    Attack Scenario: {label}")
        print(f"      Threat Probability: {res['current']['threatProbability']}")
        print(f"      Predicted Category: {res['current']['predictedCategory']} (Expected: {expected_cat})")
        print(f"      Risk Level        : {res['current']['riskLevel']}")
        print(f"      Alert Generated   : {res['alert'] is not None}")
        print(f"      Explanation ID    : {res['xai']['explanationId']}")
        print(f"      Executive Summary : {res['xai']['summary']}")

        assert res["current"]["predictedCategory"] == expected_cat
        assert res["current"]["riskLevel"] in ("HIGH", "CRITICAL")
        assert res["alert"] is not None
        assert res["alert"]["predictedCategory"] == expected_cat
        assert len(res["alert"]["topContributingFeatures"]) > 0

        # Verify explanations dynamically adapt to observed features
        narrative = (res["xai"]["summary"] + " " + res["xai"]["detailed"] + " " + " ".join(res["xai"]["evidence"])).lower()
        matched = any(term in narrative for term in expected_terms)
        assert matched, f"Explanation narrative did not contain expected feature terms: {expected_terms}"

    print("\n    [PASS] All 6 attack scenarios detected, categorized, explained, and alerted.")

    # 3. Dual-Horizon Prediction Coexistence Audit
    print("\n[3/5] Auditing Dual-Horizon Prediction Coexistence (Current vs Future)...")
    sample_attack = unified_explainable_pipeline.alert_history[-1]
    print(f"    Current Threat Probability : {sample_attack.threatProbabilityFormatted}")
    print(f"    Future Threat Probability  : {sample_attack.futureThreatProbabilityFormatted}")
    print(f"    Early Warning Status       : {sample_attack.earlyWarningStatus}")
    print(f"    Lead Time Runway           : {sample_attack.leadTimeFormatted}")

    assert sample_attack.threatProbabilityFormatted is not None
    assert sample_attack.futureThreatProbabilityFormatted is not None
    assert sample_attack.earlyWarningStatus is not None
    print("    [PASS] Current and Future threat intelligence coexist distinctly in alert.")

    # 4. Digital Twin State Synchronization & Non-Destructive History
    print("\n[4/5] Auditing Digital Twin Device State & History Lineage...")
    victim_state = unified_explainable_pipeline.device_states["VICTIM-PORT_SCAN"]
    print(f"    Twin Security Status       : {victim_state['securityStatus']}")
    print(f"    Linked Explanation ID      : {victim_state['explanationId']}")
    print(f"    Current Threat Probability : {victim_state['currentThreatProbability']}")
    print(f"    Risk Score                 : {victim_state['riskScore']}")

    assert victim_state["securityStatus"] == "AT_RISK"
    assert victim_state["explanationId"].startswith("EXP-")
    assert len(unified_explainable_pipeline.prediction_history) == 11  # 5 normal + 6 attacks
    assert len(unified_explainable_pipeline.xai_history) == 11
    assert len(unified_explainable_pipeline.alert_history) == 6
    print("    [PASS] Digital Twin state updated; complete historical audit log preserved.")

    # 5. Enriched SOC Alert Formatting Audit
    print("\n[5/5] Auditing Enriched SOC Alert ASCII Formatting...")
    soc_disp = sample_attack.to_soc_display()
    print(soc_disp)
    assert "ENRICHED SECURITY ALERT" in soc_disp
    assert "PRIMARY CONTRIBUTING FACTORS" in soc_disp
    assert "EXPLANATION NARRATIVE" in soc_disp
    print("    [PASS] Enriched Security Alert formatting validated.")

    print("\n" + "=" * 80)
    print("       ALL DAY 124 UNIFIED XAI & SECURITY INTEGRATION TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day124_suite()