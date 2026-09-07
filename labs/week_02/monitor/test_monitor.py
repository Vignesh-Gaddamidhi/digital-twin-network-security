import sys
from pathlib import Path
import time

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import rdpcap, Ether, IP, TCP, Raw
from labs.week_02.monitor.network_monitor import NetworkMonitorEngine

def run_monitor_test():
    print("================================================================================")
    print("       WEEK 2 - DAY 13: REAL-TIME NETWORK MONITORING & TELEMETRY LAB            ")
    print("================================================================================\n")

    monitor = NetworkMonitorEngine()
    pcap_file = "labs/week_02/pcap/synthetic_traffic.pcap"
    
    print(f"[*] Streaming packets from PCAP capture: {pcap_file}")
    packets = rdpcap(pcap_file)

    # Construct an explicit, controlled anomaly packet (reconnaissance scan to port 4444)
    anomaly_pkt = (
        Ether(src="00:50:56:FE:01:99", dst="00:50:56:FE:01:10") /
        IP(src="192.168.1.99", dst="192.168.1.10") /
        TCP(sport=59876, dport=4444, flags="S") /
        Raw(load=b"SCAN_PROBE_EXPLOIT_TEST")
    )
    packets.append(anomaly_pkt)

    print("\n--- LIVE PACKET TELEMETRY STREAM ---")
    for pkt in packets:
        event = monitor.process_packet(pkt)
        if event:
            alert_tag = f"[{event['alert']['level']}]"
            print(f"{event['timestamp']} | {event['source_ip']:14s} -> {event['destination_ip']:14s} | {event['protocol']:4s} | Port: {event['destination_port']:<5} | {event['packet_length']:4d} B | {alert_tag}")
            if event['alert']['level'] in ("WARNING", "CRITICAL"):
                print(f"    >>> ALERT TRIGGERED: {event['alert']['reason']}")

    # Render Dashboard Summary
    dashboard = monitor.render_dashboard()
    print("\n================================================================================")
    print("                      MONITORING METRIC DASHBOARD                               ")
    print("================================================================================")
    print(f"Total Packets Processed : {dashboard['total_packets']}")
    print(f"Total Traffic Volume    : {dashboard['total_bytes']} Bytes")
    print(f"Throughput Rates        : {dashboard['packets_per_sec']} PPS | {dashboard['bits_per_sec']} BPS")
    print("\nProtocol Distribution   :")
    for proto, pct in dashboard['protocol_distribution'].items():
        print(f"  - {proto:6s}: {pct}%")

    print(f"\nActive Connection Table ({len(dashboard['active_connections'])} tracked):")
    print(f"{'Source':16s} {'Destination':16s} {'Proto':6s} {'Port':6s} {'Packets':8s} {'Bytes':8s} {'State':8s}")
    print("-" * 76)
    for c in dashboard['active_connections']:
        print(f"{c['source']:16s} {c['destination']:16s} {c['protocol']:6s} {str(c['port']):6s} {str(c['packets']):8s} {str(c['bytes']):8s} {c['state']:8s}")

    print(f"\nSecurity Anomalies Flagged: {dashboard['alerts_count']}")
    assert dashboard['alerts_count'] >= 1, "Failed to identify injected anomaly!"
    print("[+] Network Monitoring Lab verification completed successfully.")

if __name__ == "__main__":
    run_monitor_test()