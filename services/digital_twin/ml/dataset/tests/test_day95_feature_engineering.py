import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.dataset.schemas.dataset_models import (
    DatasetSample, BinaryLabelEnum, MulticlassLabelEnum, TelemetrySourceTypeEnum
)
from services.digital_twin.ml.dataset.features.feature_engineering_engine import feature_engineering_engine
from services.digital_twin.ml.dataset.features.feature_registry_meta import feature_registry_meta

def run_day95_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 95: ML FEATURE ENGINEERING ENGINE AUDIT")
    print("=" * 80 + "\n")

    feature_engineering_engine.clear()

    # 1. Baseline Web Sample Engineering
    print("[1/5] Auditing Feature Engineering on Web HTTPS Traffic...")
    web_sample = DatasetSample(
        sampleId="SMP-WEB-01",
        timestamp="2026-09-12T12:00:00Z",
        sourceDevice="CLIENT-01",
        destinationDevice="WEB-01",
        telemetrySource=TelemetrySourceTypeEnum.ZEEK_NSM,
        protocol="TCP",
        destinationPort=443,
        service="HTTPS",
        direction="OUTBOUND",
        bytes=12000,
        packets=20,
        flowDuration=2.0,
        packetRate=10.0,
        byteRate=6000.0,
        connectionFrequency=0.5,
        failedConnections=0,
        uniquePorts=1,
        destinationDiversity=1.0,
        dnsFrequency=0.0
    )

    vec_web = feature_engineering_engine.engineer_features(web_sample)
    f_dict = vec_web.to_feature_dict()

    print(f"    packet_rate              : {vec_web.packet_rate} pkts/s")
    print(f"    bytes                    : {vec_web.bytes} B")
    print(f"    bytes_per_second         : {vec_web.bytes_per_second} B/s")
    print(f"    connection_frequency     : {vec_web.connection_frequency} conns/s")
    print(f"    port_443_ratio           : {vec_web.port_443_ratio}")
    print(f"    tcp_ratio                : {vec_web.tcp_ratio}")
    print(f"    failed_connections       : {vec_web.failed_connections}")

    assert vec_web.packet_rate == 10.0
    assert vec_web.bytes == 12000
    assert vec_web.bytes_per_second == 6000.0
    assert vec_web.port_443_ratio == 1.0
    assert vec_web.port_80_ratio == 0.0
    assert vec_web.tcp_ratio == 1.0
    assert vec_web.failed_connections == 0
    print("    [PASS] Web HTTPS features computed correctly.")

    # 2. Port Scan / Reconnaissance Window Feature Engineering
    print("\n[2/5] Auditing Port Distribution & Unique Port Counts across Window Context...")
    scan_window = [
        DatasetSample(sampleId=f"SMP-S0{i}", sourceDevice="CLIENT-01", destinationDevice="WEB-01", telemetrySource=TelemetrySourceTypeEnum.ATTACK_SCENARIO, protocol="TCP", destinationPort=p, service="PORT_ACTIVITY", direction="OUTBOUND", bytes=60, packets=1, flowDuration=0.5, scenarioId="SCN-PORTSCAN-001", failedConnections=1)
        for i, p in enumerate([21, 22, 23, 25, 80, 443, 8080])
    ]

    vec_scan = feature_engineering_engine.engineer_features(scan_window[0], window_context=scan_window)
    print(f"    unique_destination_ports : {vec_scan.unique_destination_ports}")
    print(f"    port_22_ratio            : {vec_scan.port_22_ratio:.3f}")
    print(f"    port_80_ratio            : {vec_scan.port_80_ratio:.3f}")
    print(f"    port_other_ratio         : {vec_scan.port_other_ratio:.3f}")
    print(f"    failed_connections       : {vec_scan.failed_connections}")
    print(f"    failed_connection_rate   : {vec_scan.failed_connection_rate:.3f}")

    assert vec_scan.unique_destination_ports == 7
    assert vec_scan.port_22_ratio == round(1.0 / 7.0, 4)
    assert vec_scan.port_other_ratio > 0.4  # Ports 21, 23, 25, 8080 are categorized as other
    assert vec_scan.failed_connections == 7
    assert vec_scan.failed_connection_rate == 1.0
    print("    [PASS] Multi-port scan window decomposed into deterministic port distribution ratios.")

    # 3. DNS Frequency & UDP Protocol Distribution
    print("\n[3/5] Auditing DNS Frequency & UDP Decomposition...")
    dns_sample = DatasetSample(
        sampleId="SMP-DNS-01",
        sourceDevice="CLIENT-01",
        destinationDevice="DNS-01",
        telemetrySource=TelemetrySourceTypeEnum.SIMULATION_TRAFFIC,
        protocol="UDP",
        destinationPort=53,
        service="DNS",
        direction="OUTBOUND",
        bytes=128,
        packets=2,
        flowDuration=0.05,
        dnsFrequency=20.0
    )
    vec_dns = feature_engineering_engine.engineer_features(dns_sample)
    assert vec_dns.udp_ratio == 1.0
    assert vec_dns.tcp_ratio == 0.0
    assert vec_dns.port_53_ratio == 1.0
    assert vec_dns.dns_queries == 1
    assert vec_dns.dns_frequency == 20.0
    print("    [PASS] DNS query metrics and UDP ratios evaluated cleanly.")

    # 4. Flat Numerical Vector Ordering
    print("\n[4/5] Auditing Flat Numerical Vector for Matrix Ingestion...")
    num_vec = vec_web.to_numerical_vector()
    print(f"    Numerical Vector Dimensions: {len(num_vec)}")
    print(f"    First 8 Features           : {num_vec[:8]}")

    assert len(num_vec) == 20
    assert all(isinstance(x, float) for x in num_vec)
    print("    [PASS] 20-dimensional flat numeric vector produced with strict float typing.")

    # 5. Feature Registry Metadata & Constraint Enforcement
    print("\n[5/5] Auditing Feature Registry Specifications & Bound Enforcements...")
    specs = feature_registry_meta.list_specs()
    assert len(specs) == 20
    print(f"    Total Registered Feature Specs: {len(specs)}")

    # Ensure all 9 required categories are explicitly covered
    categories = set(s.category for s in specs)
    expected_categories = {
        "Packet Rate", "Bytes", "Connection Frequency", "Port Distribution",
        "Flow Duration", "Protocol Distribution", "Failed Connections",
        "DNS Frequency", "Destination Diversity"
    }
    assert expected_categories.issubset(categories)
    print(f"    [PASS] All 9 requested feature dimensions verified: {sorted(list(expected_categories))}")

    print("\n" + "=" * 80)
    print("       ALL DAY 95 FEATURE ENGINEERING TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day95_suite()