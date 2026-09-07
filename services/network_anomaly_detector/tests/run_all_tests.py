import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.network_anomaly_detector.tests.test_collector import test_collector
from services.network_anomaly_detector.tests.test_features import test_features
from services.network_anomaly_detector.tests.test_baseline import test_baseline
from services.network_anomaly_detector.tests.test_detector import test_detector_breakage
from services.network_anomaly_detector.tests.test_alerts import test_alerts

from services.network_anomaly_detector.detection.detector import NetworkAnomalyDetector
from services.network_anomaly_detector.alerts.alert_generator import AlertGenerator
from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.siem_engine import siem_engine
from packages.shared_types.src.events import SecurityEvent

def run_master_suite():
    print("================================================================================")
    print("       WEEK 3 - DAY 21: MASTER NETWORK ANOMALY DETECTOR AUDIT SUITE             ")
    print("================================================================================\n")

    print("[1/2] Running Modular Unit Tests...")
    test_collector()
    test_features()
    test_baseline()
    test_detector_breakage()
    test_alerts()
    print("  [+] All 5 unit test suites passed.\n")

    print("[2/2] Running End-to-End Lab Anomaly -> SIEM -> Digital Twin Pipeline...")
    bootstrap_security_grounding()

    # Train baseline
    detector = NetworkAnomalyDetector()
    baseline_windows = [
        {"packet_rate": 15.0, "byte_rate": 10000.0, "unique_destinations": 1.0, "unique_ports": 2.0, "syn_to_ack_ratio": 0.5}
        for _ in range(30)
    ]
    detector.train_baseline(baseline_windows)

    # Inject anomalous scan
    anomaly_window = {
        "packet_rate": 185.0,
        "byte_rate": 120000.0,
        "unique_destinations": 1.0,
        "unique_ports": 45.0,
        "syn_to_ack_ratio": 15.0
    }
    eval_res = detector.evaluate(anomaly_window)
    alert = AlertGenerator.generate_alert(
        evaluation=eval_res,
        source_ip="192.168.1.99",
        destination_ip="192.168.1.10",
        protocol="TCP",
        port=4444
    )

    print(f"    [+] Anomaly Score : {alert['anomaly_score']} / 100.0")
    print(f"    [+] Alert Severity: {alert['severity']}")
    print(f"    [+] Confidence    : {alert['confidence']}")
    print(f"    [+] Description   : {alert['description']}")

    # Route into SIEM & Digital Twin
    sec_event = SecurityEvent(
        source_ip=alert["source"],
        destination_ip=alert["destination"],
        destination_port=alert["port"],
        protocol=alert["protocol"],
        event_type="ANOMALY_PORT_SCAN_SURGE",
        severity=alert["severity"],
        confidence=eval_res["confidence"],
        detection_source="NETWORK_ANOMALY_DETECTOR",
        details=alert
    )
    siem_res = siem_engine.ingest_security_event(sec_event)
    target = twin_engine.node_registry["D002"]

    print(f"\n    [+] SIEM Status       : {siem_res['status']} ({siem_res['event_id']})")
    print(f"    [+] ATT&CK Mapping    : {siem_res['mitre_attack']['tactic_id']} ({siem_res['mitre_attack']['technique_name']})")
    print(f"    [+] D002 Updated State: {target.security_state}")
    print(f"    [+] D002 CIA Vector   : C={target.cia_score.confidentiality}, I={target.cia_score.integrity}, A={target.cia_score.availability}")

    assert target.security_state in ("SUSPICIOUS", "COMPROMISED"), "Target node failed to degrade under anomaly alert!"
    print("\n================================================================================")
    print("        WEEK 3 ANOMALY DETECTOR & PIPELINE VERIFIED SUCCESSFULLY                ")
    print("================================================================================")

if __name__ == "__main__":
    run_master_suite()