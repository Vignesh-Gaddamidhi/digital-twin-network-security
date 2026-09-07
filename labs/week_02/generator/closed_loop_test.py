import sys
from pathlib import Path
from collections import Counter

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_02.generator.traffic_generator import TrafficGeneratorEngine
from labs.week_02.parser.pcap_parser import PcapParser

def run_closed_loop():
    print("================================================================================")
    print("      WEEK 2 - DAY 12: CLOSED-LOOP TRAFFIC SYNTHESIS & FORENSICS LAB            ")
    print("================================================================================\n")

    cfg = "labs/week_02/generator/config.json"
    pcap_path = "labs/week_02/pcap/synthetic_traffic.pcap"
    json_path = "labs/week_02/parser/synthetic_parsed.json"

    # 1. GENERATE
    print("[1/3] Synthesizing traffic via behavioral profiles...")
    gen = TrafficGeneratorEngine(cfg)
    total_generated = gen.run_synthesis(pcap_path)

    # 2. PARSE (Closed-Loop)
    print("\n[2/3] Parsing output PCAP through Day 11 Forensics Parser...")
    parser = PcapParser(pcap_path)
    events = parser.parse_to_json(json_path)

    # 3. ANALYZE
    print("\n[3/3] Performing Closed-Loop Audit...")
    total_parsed = len(events)
    print(f"    Total Generated Frames : {total_generated}")
    print(f"    Total Parsed Frames    : {total_parsed}")

    assert total_generated == total_parsed, f"Mismatch: {total_generated} generated vs {total_parsed} parsed!"

    proto_dist = Counter(e["protocol"] for e in events)
    app_dist = Counter(e["detected_application"] for e in events)

    print("\n--- TRAFFIC PROFILE METRICS ---")
    for proto, count in proto_dist.items():
        print(f"    Protocol [{proto:6s}] : {count:02d} packets ({count/total_parsed*100:.1f}%)")
    for app, count in app_dist.items():
        print(f"    Application [{app:6s}] : {count:02d} packets ({count/total_parsed*100:.1f}%)")

    print("\n[+] Closed-Loop validation successful: 100% of generated profile packets verified.")

if __name__ == "__main__":
    run_closed_loop()