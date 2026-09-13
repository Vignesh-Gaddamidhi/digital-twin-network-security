import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.prediction.end_to_end_prediction_pipeline import end_to_end_prediction_pipeline
from services.digital_twin.ml.risk.risk_models import (
    DeviceCriticalityEnum, NetworkExposureEnum, VulnerabilityStatusEnum
)

def run_day111_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 111: END-TO-END ATTACK PREDICTION PIPELINE AUDIT")
    print("=" * 80 + "\n")

    end_to_end_prediction_pipeline.clear()

    # 1. Normal HTTP Scenario
    print("[1/7] Testing Controlled Scenario 1: Normal HTTP Traffic...")
    res_norm = end_to_end_prediction_pipeline.execute_pipeline(
        features={"packet_rate": -0.8, "bytes": -0.8, "connection_frequency": -0.5, "tcp_ratio": 0.8},
        source="CLIENT-01",
        destination="WEB-01",
        device_id="WEB-01",
        device_criticality=DeviceCriticalityEnum.MEDIUM,
        network_exposure=NetworkExposureEnum.INTERNAL_ROUTABLE,
        vulnerability_status=VulnerabilityStatusEnum.NONE_KNOWN
    )
    print(f"    Threat Class      : {res_norm['threatClass']}")
    print(f"    Predicted Category: {res_norm['predictedCategory']}")
    print(f"    Risk Level        : {res_norm['riskLevel']}")
    print(f"    Device State      : {res_norm['digitalTwinState']['state']}")

    assert res_norm["threatClass"] == "NORMAL"
    assert res_norm["predictedCategory"] == "NORMAL"
    assert res_norm["riskLevel"] == "LOW"
    assert res_norm["digitalTwinState"]["state"] == "NORMAL"
    print("    [PASS] Normal HTTP classified with LOW risk and NORMAL state.")

    # 2. Port-Scan Scenario
    print("\n[2/7] Testing Controlled Scenario 2: Reconnaissance Port Scan...")
    res_scan = end_to_end_prediction_pipeline.execute_pipeline(
        features={"unique_destination_ports": 3.0, "port_other_ratio": 2.5, "failed_connections": 2.0},
        source="ATTACKER-01",
        destination="DATABASE-01",
        device_id="DATABASE-01",
        device_criticality=DeviceCriticalityEnum.HIGH,
        network_exposure=NetworkExposureEnum.EXTERNAL_FACING,
        vulnerability_status=VulnerabilityStatusEnum.OPEN_UNPATCHED
    )
    print(f"    Threat Class      : {res_scan['threatClass']}")
    print(f"    Predicted Category: {res_scan['predictedCategory']}")
    print(f"    Risk Level        : {res_scan['riskLevel']}")
    print(f"    Device State      : {res_scan['digitalTwinState']['state']}")

    assert res_scan["threatClass"] == "THREAT"
    assert res_scan["predictedCategory"] == "PORT_SCAN"
    assert res_scan["riskLevel"] in ("HIGH", "CRITICAL")
    assert res_scan["digitalTwinState"]["state"] in ("SUSPICIOUS", "AT_RISK")
    print("    [PASS] Port scan detected and elevated to AT_RISK.")

    # 3. DoS Traffic Spike Scenario
    print("\n[3/7] Testing Controlled Scenario 3: Volumetric DoS Saturation...")
    res_dos = end_to_end_prediction_pipeline.execute_pipeline(
        features={"packet_rate": 4.0, "bytes_per_second": 3.5, "flow_duration": -0.8},
        source="BOT-01",
        destination="WEB-01",
        device_id="WEB-01",
        device_criticality=DeviceCriticalityEnum.HIGH
    )
    assert res_dos["threatClass"] == "THREAT"
    assert res_dos["predictedCategory"] == "DOS_LIKE"
    print("    [PASS] DoS traffic spike identified with DOS_LIKE category.")

    # 4. DNS Anomaly Scenario
    print("\n[4/7] Testing Controlled Scenario 4: Suspicious DNS Tunneling...")
    res_dns = end_to_end_prediction_pipeline.execute_pipeline(
        features={"dns_queries": 3.5, "dns_frequency": 3.5, "port_53_ratio": 3.0, "udp_ratio": 2.0},
        source="CLIENT-02",
        destination="DNS-SRV",
        device_id="DNS-SRV"
    )
    assert res_dns["threatClass"] == "THREAT"
    assert res_dns["predictedCategory"] == "DNS_ANOMALY"
    print("    [PASS] DNS tunneling categorized correctly.")

    # 5. C2 Beaconing Scenario
    print("\n[5/7] Testing Controlled Scenario 5: Command & Control Beaconing...")
    res_beacon = end_to_end_prediction_pipeline.execute_pipeline(
        features={"connection_frequency": 2.0, "flow_duration": 2.5, "tcp_ratio": 1.0},
        source="WORKSTATION-05",
        destination="C2-SERVER",
        device_id="WORKSTATION-05"
    )
    assert res_beacon["threatClass"] == "THREAT"
    assert res_beacon["predictedCategory"] == "BEACONING"
    print("    [PASS] C2 beaconing categorized correctly.")

    # 6. Lateral Movement & Data Exfiltration Scenarios
    print("\n[6/7] Testing Controlled Scenarios 6 & 7: Lateral Movement & Exfiltration...")
    res_lateral = end_to_end_prediction_pipeline.execute_pipeline(
        features={"destination_diversity": 3.5, "unique_destination_ratio": 3.0, "port_443_ratio": 1.5},
        source="WORKSTATION-05",
        destination="DC-01",
        device_id="DC-01"
    )
    assert res_lateral["predictedCategory"] == "LATERAL_MOVEMENT_LIKE"

    res_exfil = end_to_end_prediction_pipeline.execute_pipeline(
        features={"bytes": 4.0, "bytes_per_second": 4.0, "flow_duration": 2.0},
        source="DB-SRV",
        destination="EXT-DROP",
        device_id="DB-SRV",
        device_criticality=DeviceCriticalityEnum.MISSION_CRITICAL,
        network_exposure=NetworkExposureEnum.EXTERNAL_FACING,
        vulnerability_status=VulnerabilityStatusEnum.OPEN_UNPATCHED
    )
    assert res_exfil["predictedCategory"] == "EXFILTRATION_LIKE"
    assert res_exfil["riskLevel"] == "CRITICAL"
    print("    [PASS] Lateral movement and exfiltration profiles verified.")

    # 7. Invariants & Security Alert Engine Audit
    print("\n[7/7] Auditing State Invariants, Alert Engine, and History Lineage...")
    # Invariant: ML output alone never sets COMPROMISED
    db_state = end_to_end_prediction_pipeline.device_registry["DB-SRV"]
    print(f"    Exfiltration Target Device State: {db_state.state}")
    assert db_state.state == "AT_RISK"
    assert db_state.state != "COMPROMISED"

    # Alert generation verification
    assert len(end_to_end_prediction_pipeline.alert_log) > 0
    sample_alert = end_to_end_prediction_pipeline.alert_log[-1]
    print(f"    Generated Alert Type : {sample_alert['alertType']}")
    print(f"    Alert Severity       : {sample_alert['severity']}")
    print(f"    Threat Probability   : {sample_alert['threatProbability']}")
    print(f"    Predicted Category   : {sample_alert['predictedCategory']}")
    print(f"    Risk Score           : {sample_alert['riskScore']}")

    assert sample_alert["alertType"] == "ML_ATTACK_PREDICTION"
    assert sample_alert["severity"] in ("HIGH", "CRITICAL")
    assert sample_alert["deviceId"] == "DB-SRV"

    # History count verification
    web_state = end_to_end_prediction_pipeline.device_registry["WEB-01"]
    assert len(web_state.predictionHistory) == 2  # Handled Scenario 1 and Scenario 3
    print("    [PASS] Device history lineage and alert generation confirmed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 111 END-TO-END PREDICTION PIPELINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day111_suite()