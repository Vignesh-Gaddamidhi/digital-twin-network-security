import sys
import socket
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_02.parser.pcap_parser import PcapParser
from labs.week_02.monitor.network_monitor import NetworkMonitorEngine
from scapy.all import Ether, Raw, wrpcap

def run_resiliency_audit():
    print("================================================================================")
    print("           WEEK 2 - DAY 14: FAULT INJECTION & RESILIENCY AUDIT                  ")
    print("================================================================================")

    # Scenario 1: Connection Refusal Handling
    print("\n[+] SCENARIO 1: Connection Refusal on Inactive Socket (Port 64444)")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(0.5)
    try:
        client.connect(("127.0.0.1", 64444))
        print("    [FAIL] Unexpected connection success.")
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"    [PASS] Gracefully trapped connection failure: {type(e).__name__}")
    finally:
        client.close()

    # Scenario 2: Empty PCAP Parsing
    print("\n[+] SCENARIO 2: Empty PCAP File Ingestion")
    empty_pcap = "labs/week_02/pcap/empty.pcap"
    wrpcap(empty_pcap, [])
    parser = PcapParser(empty_pcap)
    events = parser.parse_to_json()
    assert len(events) == 0, "Empty PCAP should produce 0 events"
    print("    [PASS] Empty PCAP handled without parser crash (returned 0 events)")

    # Scenario 3: Malformed Packet Handling in Monitor
    print("\n[+] SCENARIO 3: Truncated / Non-IP Packet Processing")
    monitor = NetworkMonitorEngine()
    truncated_frame = Ether() / Raw(load=b"\x00\x01\x02\xFF\xFE\xFD")
    result = monitor.process_packet(truncated_frame)
    assert result is None, "Non-IP frame should be ignored gracefully"
    print("    [PASS] Non-IP raw packet ignored safely without unhandled exception")

    print("\n[+] All 3 fault-injection scenarios passed resiliency verification.")

if __name__ == "__main__":
    run_resiliency_audit()