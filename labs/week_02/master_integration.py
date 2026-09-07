import sys
import json
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from labs.week_02.generator.traffic_generator import TrafficGeneratorEngine
from labs.week_02.parser.pcap_parser import PcapParser
from labs.week_02.monitor.network_monitor import NetworkMonitorEngine
from packages.shared_types.src.events import NetworkEvent
from scapy.all import rdpcap, Ether, IP, TCP, Raw

def run_master_pipeline():
    print("================================================================================")
    print("      WEEK 2 - DAY 14: MASTER INTEGRATION PIPELINE & TWIN SYNC                  ")
    print("================================================================================\n")

    cfg = "labs/week_02/generator/config.json"
    pcap_file = "labs/week_02/pcap/master_run.pcap"
    json_file = "labs/week_02/parser/master_events.json"

    # 1. Traffic Generation
    print("[1/5] Running Traffic Generator (Web, DNS, ICMP)...")
    gen = TrafficGeneratorEngine(cfg)
    total_generated = gen.run_synthesis(pcap_file)

    # Append an injected scan frame for anomaly verification
    scan_pkt = (
        Ether(src="00:50:56:FE:01:99", dst="00:50:56:FE:01:10") /
        IP(src="192.168.1.99", dst="192.168.1.10") /
        TCP(sport=61234, dport=4444, flags="S") /
        Raw(load=b"SCAN_TEST_PAYLOAD")
    )
    from scapy.all import wrpcap
    all_packets = rdpcap(pcap_file)
    all_packets.append(scan_pkt)
    wrpcap(pcap_file, all_packets)
    print(f"    [+] Total Packets in Master Capture: {len(all_packets)}")

    # 2. Parsing & JSON Schema Extraction
    print("\n[2/5] Parsing PCAP to Structured Events...")
    parser = PcapParser(pcap_file)
    raw_events = parser.parse_to_json(json_file)

    # 3. Normalizing to Canonical NetworkEvent Schema
    print("\n[3/5] Normalizing to Canonical NetworkEvent schema...")
    canonical_events = []
    for raw in raw_events:
        direction = "INTERNAL"
        if raw["destination_ip"] and raw["destination_ip"].startswith("203."):
            direction = "OUTBOUND"
        elif raw["source_ip"] and raw["source_ip"].startswith("192.168.1.99"):
            direction = "INBOUND"

        event = NetworkEvent(
            timestamp=raw["timestamp"],
            source_ip=raw["source_ip"] or "0.0.0.0",
            destination_ip=raw["destination_ip"] or "0.0.0.0",
            source_mac=raw["source_mac"],
            destination_mac=raw["destination_mac"],
            source_port=raw["source_port"],
            destination_port=raw["destination_port"],
            protocol=raw["protocol"],
            detected_app=raw["detected_application"],
            packet_size=raw["packet_length"],
            direction=direction,
            metadata={"tcp_flags": raw["tcp_flags"], "entropy": raw["payload_entropy"]}
        )
        canonical_events.append(event)
    print(f"    [+] Successfully normalized {len(canonical_events)} NetworkEvents.")

    # 4. Stream Through Real-Time Monitor
    print("\n[4/5] Ingesting Events into Network Monitoring Engine...")
    monitor = NetworkMonitorEngine()
    for pkt in all_packets:
        monitor.process_packet(pkt)
    dashboard = monitor.render_dashboard()
    print(f"    [+] Monitored Packets: {dashboard['total_packets']}")
    print(f"    [+] Active Sessions Tracked: {len(dashboard['active_connections'])}")
    print(f"    [+] Anomalies Flagged: {dashboard['alerts_count']}")

    # 5. Ingest into Digital Twin Core API
    print("\n[5/5] Ingesting Network Events into Digital Twin API...")
    twin_endpoint = "http://127.0.0.1:8000/api/v1/twin/ingest/packet"
    api_ingested = 0
    for evt in canonical_events:
        if evt.protocol == "TCP" and evt.source_port and evt.destination_port:
            payload = json.dumps({
                "source_ip": evt.source_ip,
                "destination_ip": evt.destination_ip,
                "protocol": evt.protocol,
                "source_port": evt.source_port,
                "destination_port": evt.destination_port,
                "tcp_flags": evt.metadata.get("tcp_flags"),
                "packet_bytes": evt.packet_size
            }).encode("utf-8")
            try:
                req = urllib.request.Request(twin_endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=1.0) as res:
                    if res.getcode() == 200:
                        api_ingested += 1
            except Exception:
                pass  # If API server is not running during standalone CLI execution, skip gracefully

    print(f"    [+] Digital Twin API Ingestion Completed: {api_ingested} socket sessions synchronized.")
    print("\n================================================================================")
    print("              MASTER INTEGRATION PIPELINE RUN SUCCESSFUL                        ")
    print("================================================================================")

if __name__ == "__main__":
    run_master_pipeline()