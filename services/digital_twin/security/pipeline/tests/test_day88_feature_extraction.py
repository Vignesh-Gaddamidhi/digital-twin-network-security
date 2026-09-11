import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.security.pipeline.normalization.canonical_event import (
    CanonicalEvent, CanonicalDetectionSourceEnum, CanonicalProtocolEnum, CanonicalSeverityEnum
)
from services.digital_twin.security.pipeline.features.feature_definitions import (
    SecurityFeatureVector, FeatureWindowEnum
)
from services.digital_twin.security.pipeline.features.feature_registry import feature_registry
from services.digital_twin.security.pipeline.features.feature_extractor import feature_extraction_engine

def run_day88_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 88: FEATURE EXTRACTION LAYER AUDIT")
    print("=" * 80 + "\n")

    feature_extraction_engine.clear()
    base_t = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Volume & Rate Extraction Audit (5s Window)
    print("[1/7] Auditing Volume Dimension (Packet/Byte Rates in 5s Window)...")
    for i in range(5):
        ts = (base_t + timedelta(seconds=i * 0.8)).isoformat()
        evt = CanonicalEvent(
            eventTimestamp=ts,
            source="CLIENT-01",
            destination="WEB-01",
            protocol=CanonicalProtocolEnum.TCP,
            port=443,
            eventType="HTTPS_CONNECTION",
            detectionSource=CanonicalDetectionSourceEnum.ZEEK,
            bytes=1000,
            packets=2
        )
        vec5 = feature_extraction_engine.ingest_and_extract(evt, FeatureWindowEnum.WINDOW_5S)

    print(f"    Packets Count   : {vec5.packetCount}")
    print(f"    Bytes Count     : {vec5.byteCount}")
    print(f"    Packet Rate     : {vec5.packetRate} pkts/s")
    print(f"    Byte Rate       : {vec5.byteRate} bytes/s")

    assert vec5.packetCount == 10
    assert vec5.byteCount == 5000
    assert vec5.packetRate == 2.0  # 10 packets / 5s
    assert vec5.byteRate == 1000.0 # 5000 bytes / 5s
    print("    [PASS] Volume features accurately aggregated over 5s window.")

    # 2. Connection Dimension (Failed Connection Ratio)
    print("\n[2/7] Auditing Connection Dimension & Failed Connection Ratio...")
    for i in range(3):
        ts = (base_t + timedelta(seconds=4.0 + i * 0.2)).isoformat()
        evt_fail = CanonicalEvent(
            eventTimestamp=ts,
            source="CLIENT-01",
            destination="WEB-01",
            protocol=CanonicalProtocolEnum.TCP,
            port=22,
            eventType="AUTH_FAILURE",
            detectionSource=CanonicalDetectionSourceEnum.SURICATA,
            bytes=200,
            packets=1,
            metadata={"conn_state": "REJ"}
        )
        vec_conn = feature_extraction_engine.ingest_and_extract(evt_fail, FeatureWindowEnum.WINDOW_5S)

    print(f"    Total Connections  : {vec_conn.connectionCount}")
    print(f"    Failed Connections : {vec_conn.failedConnectionCount}")
    print(f"    Failed Ratio       : {vec_conn.failedConnectionRatio}")

    assert vec_conn.failedConnectionCount == 3
    assert vec_conn.failedConnectionRatio > 0.3
    print("    [PASS] Failed connection tracking verified.")

    # 3. Port Dimension & Sweep Detection
    print("\n[3/7] Auditing Port Dimension (Unique Ports Probed)...")
    probe_ports = [21, 23, 25, 8080, 8443]
    for idx, p in enumerate(probe_ports):
        ts = (base_t + timedelta(seconds=4.5 + idx * 0.1)).isoformat()
        evt_scan = CanonicalEvent(
            eventTimestamp=ts,
            source="CLIENT-01",
            destination="WEB-01",
            protocol=CanonicalProtocolEnum.TCP,
            port=p,
            eventType="PORT_ACTIVITY",
            detectionSource=CanonicalDetectionSourceEnum.SURICATA,
            bytes=60,
            packets=1
        )
        vec_port = feature_extraction_engine.ingest_and_extract(evt_scan, FeatureWindowEnum.WINDOW_5S)

    print(f"    Unique Ports Observed in 5s: {vec_port.uniqueDestinationPorts}")
    assert vec_port.uniqueDestinationPorts >= 5
    print("    [PASS] Port sweep diversity captured in uniqueDestinationPorts.")

    # 4. Timing Dimension (C2 Beaconing Near-Zero Variance)
    print("\n[4/7] Auditing Timing Dimension (Low-Jitter Periodic Beaconing)...")
    feature_extraction_engine.clear()
    beacon_base = datetime(2026, 9, 11, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(10):
        # Precise 1.0s interval
        ts = (beacon_base + timedelta(seconds=float(i) * 1.0)).isoformat()
        b_evt = CanonicalEvent(
            eventTimestamp=ts,
            source="CLIENT-01",
            destination="SERVER-01",
            protocol=CanonicalProtocolEnum.TCP,
            port=443,
            eventType="HTTPS_CONNECTION",
            detectionSource=CanonicalDetectionSourceEnum.ZEEK,
            bytes=120,
            packets=1
        )
        vec_beacon = feature_extraction_engine.ingest_and_extract(b_evt, FeatureWindowEnum.WINDOW_30S)

    print(f"    Average Interval   : {vec_beacon.averageInterval}s")
    print(f"    Interval Variance  : {vec_beacon.intervalVariance}s²")

    assert vec_beacon.averageInterval == 1.0
    assert vec_beacon.intervalVariance < 0.001
    print("    [PASS] Periodic beaconing confirmed with near-zero timing variance (< 0.001s²).")

    # 5. Direction Dimension (Exfiltration Asymmetry)
    print("\n[5/7] Auditing Direction Dimension (Egress vs Ingress Ratios)...")
    feature_extraction_engine.clear()
    exfil_ts = datetime(2026, 9, 11, 15, 0, 0, tzinfo=timezone.utc).isoformat()
    exfil_evt = CanonicalEvent(
        eventTimestamp=exfil_ts,
        source="CLIENT-01",
        destination="EXTERNAL-C2",
        protocol=CanonicalProtocolEnum.TCP,
        port=443,
        eventType="HTTPS_CONNECTION",
        detectionSource=CanonicalDetectionSourceEnum.SURICATA,
        bytes=250000,
        packets=200,
        metadata={"direction": "OUTBOUND"}
    )
    vec_exfil = feature_extraction_engine.ingest_and_extract(exfil_evt, FeatureWindowEnum.WINDOW_5S)
    print(f"    Outbound Bytes     : {vec_exfil.outboundBytes}")
    print(f"    Inbound Bytes      : {vec_exfil.inboundBytes}")
    print(f"    Direction Ratio    : {vec_exfil.bytesDirectionRatio}")

    assert vec_exfil.outboundBytes == 250000
    assert vec_exfil.bytesDirectionRatio > 1000.0
    print("    [PASS] Outbound flow asymmetry captured cleanly in direction features.")

    # 6. Multi-Window Extraction (5s, 30s, 60s)
    print("\n[6/7] Auditing Multi-Window Extraction (5s vs 30s vs 60s)...")
    multi_win = feature_extraction_engine.extract_multi_window(exfil_evt)
    assert "5s" in multi_win
    assert "30s" in multi_win
    assert "60s" in multi_win
    assert multi_win["5s"].windowDurationSeconds == 5.0
    assert multi_win["30s"].windowDurationSeconds == 30.0
    assert multi_win["60s"].windowDurationSeconds == 60.0
    print("    [PASS] Multi-window extraction evaluated across 5s, 30s, and 60s.")

    # 7. Feature Registry Descriptors & Validation Constraints
    print("\n[7/7] Auditing Feature Registry Descriptors & Invariant Enforcement...")
    descriptors = feature_registry.list_descriptors()
    assert len(descriptors) >= 10
    print(f"    Total Registered Feature Descriptors: {len(descriptors)}")

    # Test invalid vector rejection
    invalid_vec = vec_exfil.model_copy(update={"packetRate": -5.0})
    errs = feature_registry.validate_vector(invalid_vec)
    assert any("packetRate cannot be negative" in e for e in errs)
    print(f"    [PASS] Registry validation guardrails intercepted invalid feature vector: {errs}")

    print("\n" + "=" * 80)
    print("       ALL DAY 88 FEATURE EXTRACTION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day88_suite()