import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, Raw
from services.network_anomaly_detector.features.feature_extractor import NetworkFeatureWindow
from services.network_anomaly_detector.detection.baseline_engine import StatisticalBaselineEngine
from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.siem_engine import siem_engine
from packages.shared_types.src.events import SecurityEvent

def run_anomaly_detector_test():
    print("================================================================================")
    print("      WEEK 3 - DAY 20: NETWORK ANOMALY DETECTOR BASELINE & CONTAINMENT TEST      ")
    print("================================================================================\n")

    bootstrap_security_grounding()

    # 1. Establish Baseline Dataset (20 consecutive benign windows)
    print("[1/4] Training Statistical Baseline from Benign Traffic Windows...")
    benign_windows = []
    for i in range(20):
        window_packets = []
        # Normal web & DNS packets
        for _ in range(10):
            p = Ether() / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=50000, dport=80, flags="A") / Raw(load=b"BENIGN_HTTP")
            window_packets.append(p)
        features = NetworkFeatureWindow.extract_window_features(window_packets, duration_sec=1.0)
        benign_windows.append(features)

    detector = StatisticalBaselineEngine()
    stats = detector.train_baseline(benign_windows)
    print(f"    [+] Baseline Trained across {len(benign_windows)} observations.")
    print(f"    [+] PPS Baseline : {stats['packets_per_sec']['mean']} +/- {stats['packets_per_sec']['std_dev']}")
    print(f"    [+] Port Baseline: {stats['unique_dst_ports']['mean']} +/- {stats['unique_dst_ports']['std_dev']}")

    # 2. Test Benign Traffic Evaluation
    print("\n[2/4] Testing Benign Verification Window (Expect 0 Anomalies)...")
    clean_packets = [
        Ether() / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=50001, dport=80, flags="A") / Raw(load=b"BENIGN_SAMPLE")
        for _ in range(10)
    ]
    clean_features = NetworkFeatureWindow.extract_window_features(clean_packets, duration_sec=1.0)
    false_positives = detector.evaluate_vector(clean_features, z_threshold=3.0)
    assert len(false_positives) == 0, f"False positive triggered: {false_positives}"
    print("    [PASS] Clean window generated 0 anomaly alerts.")

    # 3. Inject Anomalous Traffic (Massive Port Reconnaissance Scan)
    print("\n[3/4] Injecting Anomalous Multi-Port Scan (Ports 1000 - 1050)...")
    scan_packets = []
    for p_num in range(1000, 1050):
        scan_pkt = Ether() / IP(src="192.168.1.99", dst="192.168.1.10") / TCP(sport=55000, dport=p_num, flags="S")
        scan_packets.append(scan_pkt)

    attack_features = NetworkFeatureWindow.extract_window_features(scan_packets, duration_sec=1.0)
    anomalies = detector.evaluate_vector(attack_features, z_threshold=3.0)
    
    assert len(anomalies) > 0, "Anomaly detector failed to trigger on multi-port scan!"
    print(f"    [+] Anomalies Flagged: {len(anomalies)}")
    for a in anomalies:
        print(f"        >>> Feature: {a['feature']} | Observed: {a['observed_value']} | Z-Score: {a['z_score']} | Severity: {a['severity']}")

    # 4. Digital Twin Automated Containment Verification
    print("\n[4/4] Ingesting Anomaly Alert into SIEM -> Digital Twin Containment...")
    top_anomaly = anomalies[0]
    sec_event = SecurityEvent(
        source_ip="192.168.1.99",
        destination_ip="192.168.1.10",
        destination_port=1000,
        protocol="TCP",
        event_type="ANOMALY_PORT_SCAN_SURGE",
        severity=top_anomaly["severity"],
        confidence=0.96,
        detection_source="NETWORK_ANOMALY_DETECTOR",
        details={"z_score": top_anomaly["z_score"], "feature": top_anomaly["feature"]}
    )

    ingest_res = siem_engine.ingest_security_event(sec_event)
    target_node = twin_engine.node_registry["D002"]
    print(f"    [+] SIEM Event Ingested: {ingest_res['event_id']}")
    print(f"    [+] Digital Twin D002 State: {target_node.security_state}")
    print(f"    [+] D002 CIA Posture: C={target_node.cia_score.confidentiality}, I={target_node.cia_score.integrity}, A={target_node.cia_score.availability}")

    assert target_node.security_state in ("SUSPICIOUS", "COMPROMISED"), "Target node state did not degrade under active anomaly alert!"
    print("\n[+] Full Anomaly Detection, Baseline Profiling, and Twin Containment pipeline verified.")

if __name__ == "__main__":
    run_anomaly_detector_test()