import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from frontend.traffic.traffic_models import (
    TrafficTimeRange, TrafficAnomalyType, TrafficPointDetail
)
from frontend.traffic.traffic_monitoring_engine import traffic_monitoring_engine

def run_day145_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 145: TRAFFIC MONITORING PANEL AUDIT")
    print("=" * 80 + "\n")

    traffic_monitoring_engine._seed_baseline_traffic()

    # 1. Traffic Chart & Sparkline Rendering
    print("[1/9] Auditing Traffic Panel Generation & ASCII Throughput Chart...")
    snapshot = traffic_monitoring_engine.generate_traffic_snapshot(TrafficTimeRange.RANGE_30M)
    chart = snapshot.render_cli_chart()
    print(chart)

    assert snapshot.currentPacketRate > 0.0
    assert snapshot.currentByteRate > 0.0
    assert len(snapshot.series) > 0
    assert "TRAFFIC MONITORING PANEL" in chart
    print("    [PASS] Traffic chart and metrics rendered cleanly.")

    # 2. Protocol Distribution Validation
    print("\n[2/9] Auditing Protocol Breakdown (TCP, UDP, ICMP, HTTP, HTTPS, DNS, SSH)...")
    pb = snapshot.protocolBreakdown
    print(f"    TCP   : {pb.tcp}%")
    print(f"    HTTPS : {pb.https}%")
    print(f"    DNS   : {pb.dns}%")
    print(f"    HTTP  : {pb.http}%")
    print(f"    SSH   : {pb.ssh}%")

    total_pct = pb.tcp + pb.udp + pb.icmp + pb.http + pb.https + pb.dns + pb.ssh
    assert 99.0 <= total_pct <= 101.0  # Normalized percentage sum
    print("    [PASS] Protocol distributions accurately bin to 100%.")

    # 3. Packet & Byte Rate Calculations
    print("\n[3/9] Auditing Rate Calculations...")
    print(f"    Current Packet Rate : {snapshot.currentPacketRate:.1f} pkts/s")
    print(f"    Current Byte Rate   : {snapshot.currentByteRate/1024:.1f} KB/s")
    assert snapshot.currentPacketRate >= 100.0
    assert snapshot.currentByteRate >= 50000.0
    print("    [PASS] Packet and byte rates computed properly.")

    # 4. Connection Concurrency Tracking
    print("\n[4/9] Auditing Connection Tracking...")
    print(f"    Connections / sec  : {snapshot.currentConnectionsRate:.1f}")
    print(f"    Active Connections : {snapshot.currentActiveConnections}")
    assert snapshot.currentActiveConnections >= 1
    print("    [PASS] Connection metrics active.")

    # 5. Time Range Filtering
    print("\n[5/9] Auditing Multi-Interval Range Slicing (5m vs 30m vs 24h)...")
    snap_5m = traffic_monitoring_engine.generate_traffic_snapshot(TrafficTimeRange.RANGE_5M)
    snap_30m = traffic_monitoring_engine.generate_traffic_snapshot(TrafficTimeRange.RANGE_30M)
    snap_24h = traffic_monitoring_engine.generate_traffic_snapshot(TrafficTimeRange.RANGE_24H)

    print(f"    5m  Samples : {len(snap_5m.series)}")
    print(f"    30m Samples : {len(snap_30m.series)}")
    print(f"    24h Samples : {len(snap_24h.series)}")

    assert len(snap_5m.series) <= len(snap_30m.series)
    assert len(snap_30m.series) <= len(snap_24h.series)
    print("    [PASS] Time-range slicing behaves consistently.")

    # 6. Traffic Anomaly Markers (Spike Detection)
    print("\n[6/9] Auditing Traffic Anomaly Flagging (TRAFFIC_SPIKE)...")
    spike_points = [p for p in snapshot.series if p.hasAnomaly]
    print(f"    Anomalous Spikes Detected : {len(spike_points)}")
    assert len(spike_points) >= 1
    assert spike_points[0].anomalyType == TrafficAnomalyType.TRAFFIC_SPIKE
    assert spike_points[0].packetRate > 1000.0
    print("    [PASS] Traffic spikes flagged with distinct anomaly markers.")

    # 7. Traffic Drill-Down Point Inspection
    print("\n[7/9] Auditing Single-Point Drill-Down Inspection...")
    target_pt_id = spike_points[0].sampleDetail.pointId
    detail = traffic_monitoring_engine.drill_down_point(target_pt_id)
    assert detail is not None
    print(f"    Point ID    : {detail.pointId}")
    print(f"    Source      : {detail.sourceDevice} -> {detail.destinationDevice}")
    print(f"    Protocol    : {detail.protocol}:{detail.port}")
    print(f"    Event Type  : {detail.eventType}")
    print(f"    Packets     : {detail.packets} ({detail.bytesTransferred} bytes)")

    assert detail.sourceDevice == "ATTACKER-EXT"
    assert detail.eventType == "DOS_SATURATION"
    print("    [PASS] Point drill-down inspection validated.")

    # 8. Empty Traffic Zero-State
    print("\n[8/9] Auditing Empty Traffic Fallback Handling...")
    traffic_monitoring_engine.raw_samples.clear()
    snap_empty = traffic_monitoring_engine.generate_traffic_snapshot()
    print(f"    Empty Series Count : {len(snap_empty.series)}")
    assert snap_empty.currentPacketRate == 0.0
    assert snap_empty.currentActiveConnections == 0
    assert len(snap_empty.series) == 0
    print("    [PASS] Empty traffic state handled cleanly.")

    # 9. Ingestion & Dynamic Re-population
    print("\n[9/9] Auditing Live Sample Ingestion...")
    sample = TrafficPointDetail(
        timestamp="2026-09-15T12:00:00Z",
        sourceDevice="CLIENT-01",
        destinationDevice="WEB-01",
        protocol="TCP",
        port=80,
        packets=500,
        bytesTransferred=120000
    )
    traffic_monitoring_engine.ingest_traffic_sample(sample)
    assert len(traffic_monitoring_engine.raw_samples) == 1
    print("    [PASS] Live sample ingestion verified.")

    # Reset environment
    traffic_monitoring_engine._seed_baseline_traffic()

    print("\n" + "=" * 80)
    print("       ALL DAY 145 TRAFFIC MONITORING PANEL TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day145_suite()