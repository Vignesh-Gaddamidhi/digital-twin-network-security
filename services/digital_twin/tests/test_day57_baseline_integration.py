import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.simulation.generators.day57_baseline_generator import day57_generator

def run_day57_baseline_suite():
    print("=" * 80)
    print("      DAY 57: WEEK 8 GRAND INTEGRATION & NORMAL BASELINE SYNTHESIS")
    print("=" * 80 + "\n")

    # 1. Provision & Verify Canonical Topology
    print("[1/4] Provisioning Full Canonical Topology (Internet -> FW -> RTR -> SW -> Web/DNS/Client -> DB)...")
    day57_generator.provision_canonical_topology()
    dev_count = device_registry.count()
    print(f"    [PASS] Verified {dev_count} canonical devices active in registry.")
    assert dev_count >= 8

    # 2. Run Baseline Synthesis Scenario
    print("\n[2/4] Generating 60-Second Normal Baseline (normal-baseline-run-001)...")
    summary = day57_generator.generate_baseline(duration_seconds=60, seed=12345)

    print(f"    Total Packets Simulated : {summary.totalPackets}")
    print(f"    Total Bytes Transferred : {summary.totalBytes} bytes")
    print(f"    Average Traffic Rate    : {summary.trafficRateBps} Bps")
    print(f"    TCP Frames Count        : {summary.tcpCount}")
    print(f"    UDP Datagrams Count     : {summary.udpCount}")
    print(f"    ICMP Probes Count       : {summary.icmpCount}")
    print(f"    HTTP Transactions       : {summary.httpCount}")
    print(f"    HTTPS Transactions      : {summary.httpsCount}")
    print(f"    DNS Transactions        : {summary.dnsCount}")
    print(f"    SSH Sessions            : {summary.sshCount}")
    print(f"    Active Connections      : {summary.activeConnections}")
    print(f"    Avg Conns / Device      : {summary.averageConnectionsPerDevice}")

    # Core Assertions
    assert summary.totalPackets > 100
    assert summary.totalBytes > 20000
    assert summary.tcpCount > 0
    assert summary.udpCount > 0
    assert summary.icmpCount > 0
    assert summary.httpsCount == 60 # 1 per second minimum
    assert summary.dnsCount == 120  # 60 queries + 60 replies
    assert summary.sshCount > 0
    print("    [PASS] All baseline counters accurately populated.")

    # 3. Port & Protocol Distribution Validation
    print("\n[3/4] Validating Port & Protocol Distributions...")
    print("    Protocol Breakdown (%):", summary.protocolDistribution)
    print("    Top Destination Ports :", summary.portDistribution)

    assert 443 in summary.portDistribution  # HTTPS
    assert 53 in summary.portDistribution   # DNS
    assert 5432 in summary.portDistribution # DB TCP
    assert summary.protocolDistribution["TCP"] > 50.0
    assert summary.protocolDistribution["UDP"] > 10.0
    print("    [PASS] Port and protocol distributions reflect normal corporate network behavior.")

    # 4. Verify Dataset Files on Disk
    print("\n[4/4] Verifying Generated Dataset Artifacts (events.jsonl, summary.json, metadata.json)...")
    target_dir = day57_generator.output_dir
    events_file = target_dir / "events.jsonl"
    summary_file = target_dir / "summary.json"
    metadata_file = target_dir / "metadata.json"

    assert events_file.exists(), f"Missing {events_file}"
    assert summary_file.exists(), f"Missing {summary_file}"
    assert metadata_file.exists(), f"Missing {metadata_file}"

    # Read events line count
    with open(events_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    print(f"    [PASS] Found {len(lines)} event lines in events.jsonl")
    assert len(lines) == summary.totalEvents
    assert summary.totalPackets >= summary.totalEvents

    with open(summary_file, "r", encoding="utf-8") as f:
        s_data = json.load(f)
    assert s_data["totalEvents"] == summary.totalEvents
    assert s_data["totalPackets"] == summary.totalPackets

    with open(metadata_file, "r", encoding="utf-8") as f:
        m_data = json.load(f)
    assert m_data["datasetId"] == "normal-baseline-run-001"
    print("    [PASS] Dataset artifacts verified and validated against schema.")

    print("\n" + "=" * 80)
    print("   ALL DAY 57 WEEK 8 BASELINE INTEGRATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day57_baseline_suite()