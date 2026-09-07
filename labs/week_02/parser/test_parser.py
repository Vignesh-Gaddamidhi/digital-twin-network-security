import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_02.pcap.generate_lab_pcap import generate_lab_pcap
from labs.week_02.parser.pcap_parser import PcapParser

def test_pipeline():
    print("================================================================================")
    print("       WEEK 2 - DAY 11: PCAP GENERATION, PARSING & PROTOCOL DETECTION          ")
    print("================================================================================\n")

    pcap_file = "labs/week_02/pcap/lab_sample.pcap"
    json_out = "labs/week_02/parser/parsed_packets.json"

    # Step 1: Generate PCAP
    generate_lab_pcap(pcap_file)

    # Step 2: Parse to JSON
    parser = PcapParser(pcap_file)
    events = parser.parse_to_json(json_out)

    # Step 3: Validate Protocol Classification Coverage
    detected_apps = {e["detected_application"] for e in events}
    detected_l4 = {e["protocol"] for e in events}

    print("\n--- PROTOCOL DETECTION AUDIT ---")
    print(f"Layer-4 Protocols Detected: {detected_l4}")
    print(f"Layer-7 Applications Detected: {detected_apps}")

    assert "TCP" in detected_l4, "Failed to identify TCP"
    assert "UDP" in detected_l4, "Failed to identify UDP"
    assert "ICMP" in detected_l4, "Failed to identify ICMP"
    assert "HTTP" in detected_apps, "Failed to identify HTTP"
    assert "DNS" in detected_apps, "Failed to identify DNS"
    assert "TLS" in detected_apps, "Failed to identify TLS"

    print("\n[+] Verification passed: All protocol signatures recognized and JSON serialized.")

if __name__ == "__main__":
    test_pipeline()