import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.network_anomaly_detector.detection.detector import NetworkAnomalyDetector

def test_baseline():
    detector = NetworkAnomalyDetector()
    sample_windows = [
        {"packet_rate": 10.0, "byte_rate": 1000.0, "unique_destinations": 1.0, "unique_ports": 1.0, "syn_to_ack_ratio": 1.0},
        {"packet_rate": 12.0, "byte_rate": 1100.0, "unique_destinations": 1.0, "unique_ports": 1.0, "syn_to_ack_ratio": 1.0},
        {"packet_rate": 11.0, "byte_rate": 1050.0, "unique_destinations": 1.0, "unique_ports": 1.0, "syn_to_ack_ratio": 1.0}
    ]
    stats = detector.train_baseline(sample_windows)
    assert stats["packet_rate"]["mean"] == 11.0
    assert stats["unique_destinations"]["mean"] == 1.0
    print("  [PASS] test_baseline passed.")

if __name__ == "__main__":
    test_baseline()