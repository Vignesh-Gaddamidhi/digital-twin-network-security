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

    # 1. Normal Baseline Scenarios
    print("[1/5] Auditing Normal Baseline Telemetry Scenarios...")
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
        assert res["current"]["predictedCategory"] == "NORMAL"
        assert res["current"]["riskLevel"] in ("LOW", "MEDIUM")

    print("    [PASS] All 5 normal scenarios classified as benign.")

    # 2. Suspicious Attack Scenarios
    print("\n[2/5] Auditing Suspicious Attack Scenarios...")
    attack_scenarios = [
        ("PORT_SCAN", {"unique_destination_ports": 3.0, "port_other_ratio": 2.5, "failed_connections": 2.0, "connection_frequency": 2.8, "destination_diversity": 2.5}, "PORT_SCAN"),
        ("DOS_LIKE", {"packet_rate": 4.0, "bytes_per_second": 3.5, "flow_duration": -0.8, "bytes": 3.8}, "DOS_LIKE"),
        ("DNS_ANOMALY", {"dns_queries": 3.5, "dns_frequency": 3.5, "port_53_ratio": 3.0, "udp_ratio": 2.0}, "DNS_ANOMALY"),
        ("BEACONING", {"connection_frequency": 2.0, "flow_duration": 2.5, "tcp_ratio": 1.0, "destination_diversity": -0.5}, "BEACONING"),
        ("LATERAL_MOVEMENT_LIKE", {"destination_diversity": 3.5, "unique_destination_ratio": 3.0, "port_443_ratio": 1.5}, "LATERAL_MOVEMENT_LIKE"),
        ("EXFILTRATION_LIKE", {"bytes": 4.0, "bytes_per_second": 4.0, "flow_duration": 2.0}, "EXFILTRATION_LIKE")
    ]

    for label, feats, expected_cat in attack_scenarios:
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
        assert res["current"]["predictedCategory"] == expected_cat
        assert res["alert"] is not None

    print("    [PASS] All 6 attack scenarios detected, categorized, and alerted.")

    # 3. Dual-Horizon Prediction Coexistence
    print("\n[3/5] Auditing Dual-Horizon Prediction Coexistence...")
    sample_attack = unified_explainable_pipeline.alert_history[-1]
    assert sample_attack.threatProbabilityFormatted is not None
    assert sample_attack.futureThreatProbabilityFormatted is not None
    print("    [PASS] Current and Future threat intelligence coexist in alert.")

    # 4. Digital Twin State Synchronization
    print("\n[4/5] Auditing Digital Twin Device State & History Lineage...")
    assert len(unified_explainable_pipeline.prediction_history) >= 10
    print("    [PASS] Digital Twin state updated; complete historical audit log preserved.")

    # 5. Enriched SOC Alert Formatting
    print("\n[5/5] Auditing Enriched SOC Alert ASCII Formatting...")
    soc_disp = sample_attack.to_soc_display()
    assert "ENRICHED SECURITY ALERT" in soc_disp
    print("    [PASS] Enriched Security Alert formatting validated.")

    print("\n" + "=" * 80)
    print("       ALL DAY 124 UNIFIED XAI & SECURITY INTEGRATION TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day124_suite()