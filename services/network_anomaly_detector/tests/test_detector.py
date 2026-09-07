import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.network_anomaly_detector.detection.detector import NetworkAnomalyDetector

def test_detector_breakage():
    detector = NetworkAnomalyDetector()
    baseline_windows = [
        {"packet_rate": 10.0, "byte_rate": 5000.0, "unique_destinations": 1.0, "unique_ports": 2.0, "syn_to_ack_ratio": 0.5}
        for _ in range(25)
    ]
    detector.train_baseline(baseline_windows)

    # Test 1: Normal Traffic (Expect Low / Normal)
    res_normal = detector.evaluate({"packet_rate": 10.2, "byte_rate": 5100.0, "unique_destinations": 1.0, "unique_ports": 2.0, "syn_to_ack_ratio": 0.5})
    assert not res_normal["is_anomaly"], f"False positive in normal test: {res_normal}"
    assert res_normal["anomaly_score"] < 25.0

    # Test 2: High Traffic Volume Surge (Expect Anomaly)
    res_surge = detector.evaluate({"packet_rate": 150.0, "byte_rate": 80000.0, "unique_destinations": 1.0, "unique_ports": 2.0, "syn_to_ack_ratio": 0.5})
    assert res_surge["is_anomaly"], "Failed to detect packet rate volume surge!"
    assert res_surge["severity"] in ("HIGH", "CRITICAL")

    # Test 3: Horizontal Destination Sweep (Expect Anomaly)
    res_sweep = detector.evaluate({"packet_rate": 12.0, "byte_rate": 6000.0, "unique_destinations": 35.0, "unique_ports": 2.0, "syn_to_ack_ratio": 0.5})
    assert res_sweep["is_anomaly"], "Failed to detect horizontal destination sweep!"
    assert res_sweep["deviations"]["unique_destinations"]["z_score"] > 5.0

    print("  [PASS] test_detector passed all 3 breakage scenarios.")

if __name__ == "__main__":
    test_detector_breakage()