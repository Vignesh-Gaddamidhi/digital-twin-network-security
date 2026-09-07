import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.network_anomaly_detector.alerts.alert_generator import AlertGenerator

def test_alerts():
    evaluation = {
        "is_anomaly": True,
        "anomaly_score": 82.5,
        "severity": "HIGH",
        "confidence": 0.87,
        "deviations": {
            "packet_rate": {"observed": 120.0, "z_score": 6.5, "penalty": 60.0}
        }
    }
    alert = AlertGenerator.generate_alert(
        evaluation=evaluation,
        source_ip="192.168.1.99",
        destination_ip="192.168.1.10",
        protocol="TCP",
        port=80
    )
    assert alert is not None
    assert alert["severity"] == "HIGH"
    assert "Potential anomalous behaviour detected" in alert["description"]
    assert alert["confidence"] == "87%"
    assert alert["anomaly_score"] == 82.5
    print("  [PASS] test_alerts passed.")

if __name__ == "__main__":
    test_alerts()