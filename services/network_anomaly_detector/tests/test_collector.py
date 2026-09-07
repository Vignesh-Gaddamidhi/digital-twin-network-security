import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP
from services.network_anomaly_detector.collectors.traffic_collector import TrafficCollector

def test_collector():
    collector = TrafficCollector()
    pkt = Ether() / IP(src="192.168.1.11", dst="192.168.1.10") / TCP(sport=50000, dport=80)
    
    # 1. Ingest
    res = collector.ingest_packet(pkt)
    assert res["packet_count"] == 1
    assert res["destination_port"] == 80
    
    # 2. Flush
    flows = collector.flush_window()
    assert len(flows) == 1
    assert len(collector.active_flows) == 0
    print("  [PASS] test_collector passed.")

if __name__ == "__main__":
    test_collector()