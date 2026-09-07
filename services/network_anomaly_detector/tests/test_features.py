import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP
from services.network_anomaly_detector.features.feature_extractor import NetworkFeatureWindow

def test_features():
    pkts = [
        Ether() / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=50000, dport=80, flags="S"),
        Ether() / IP(src="192.168.1.11", dst="192.168.1.12") / TCP(sport=50000, dport=443, flags="A")
    ]
    feats = NetworkFeatureWindow.extract_window_features(pkts, duration_sec=1.0)
    assert feats["packet_rate"] == 2.0
    assert feats["unique_destinations"] == 2.0
    assert feats["unique_ports"] == 2.0
    print("  [PASS] test_features passed.")

if __name__ == "__main__":
    test_features()