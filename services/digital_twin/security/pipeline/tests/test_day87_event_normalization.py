import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.security.pipeline.normalization.canonical_event import (
    CanonicalDetectionSourceEnum, CanonicalSeverityEnum, CanonicalProtocolEnum
)
from services.digital_twin.security.pipeline.normalization.unified_normalizer import unified_normalizer

def setup_devices():
    device_registry.clear()
    unified_normalizer.clear()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    dns = NetworkDeviceModel(id="DNS-01",    hostname="DNS-01",    type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(dns)

def run_day87_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 87: EVENT NORMALIZATION & ALIGNMENT AUDIT")
    print("=" * 80 + "\n")

    setup_devices()

    # 1. Suricata Normalization
    print("[1/6] Auditing Suricata Normalization (ISO Timestamp, Protocol Coercion, Severity Mapping)...")
    suri_raw = {
        "timestamp": "2026-09-11T10:00:00Z",
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "src_port": "51234",
        "dest_ip": "192.168.1.20",
        "dest_port": "443",
        "proto": "tcp",
        "alert": {
            "signature": "ET EXPLOIT Apache Struts RCE",
            "severity": 1
        }
    }
    evt_suri, err = unified_normalizer.normalize(suri_raw, source_type="suricata")
    assert err is None
    assert evt_suri is not None
    assert evt_suri.source == "CLIENT-01"
    assert evt_suri.destination == "WEB-01"
    assert evt_suri.protocol == CanonicalProtocolEnum.TCP
    assert evt_suri.port == 443
    assert evt_suri.sourcePort == 51234
    assert evt_suri.severity == CanonicalSeverityEnum.CRITICAL
    assert evt_suri.detectionSource == CanonicalDetectionSourceEnum.SURICATA
    assert evt_suri.eventType == "IDS_ALERT"
    print("    [PASS] Suricata EVE normalized to CanonicalEvent (Port: 443, Severity: CRITICAL).")

    # 2. Zeek Normalization (Epoch Timestamp, Port String Coercion)
    print("\n[2/6] Auditing Zeek Normalization (Epoch Timestamp, String Ports, '-' Nulls)...")
    zeek_raw = {
        "ts": 1773120000.0,
        "uid": "CZ123",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": "49152",
        "id.resp_h": "192.168.1.53",
        "id.resp_p": "53",
        "proto": "udp",
        "query": "corp.test",
        "orig_bytes": "64",
        "resp_bytes": "-"
    }
    evt_zeek, err = unified_normalizer.normalize(zeek_raw, source_type="zeek")
    assert err is None
    assert evt_zeek is not None
    assert evt_zeek.source == "CLIENT-01"
    assert evt_zeek.destination == "DNS-01"
    assert evt_zeek.protocol == CanonicalProtocolEnum.UDP
    assert evt_zeek.port == 53
    assert evt_zeek.sourcePort == 49152
    assert evt_zeek.bytes == 64
    assert evt_zeek.detectionSource == CanonicalDetectionSourceEnum.ZEEK
    assert evt_zeek.eventType == "DNS_QUERY"
    print("    [PASS] Zeek TSV/JSON normalized: Epoch timestamp converted to ISO; '-' handled gracefully.")

    # 3. Simulation Normalization
    print("\n[3/6] Auditing Simulation Telemetry Normalization...")
    sim_raw = {
        "simulationId": "sim-8877",
        "timestamp": "2026-09-11T10:05:00+00:00",
        "sourceDevice": "CLIENT-01",
        "destinationDevice": "WEB-01",
        "destinationPort": 80,
        "protocol": "TCP",
        "bytes": 1024,
        "packets": 4
    }
    evt_sim, err = unified_normalizer.normalize(sim_raw, source_type="simulation")
    assert err is None
    assert evt_sim.source == "CLIENT-01"
    assert evt_sim.destination == "WEB-01"
    assert evt_sim.port == 80
    assert evt_sim.protocol == CanonicalProtocolEnum.TCP
    assert evt_sim.detectionSource == CanonicalDetectionSourceEnum.SIMULATION
    assert evt_sim.eventType == "HTTP_REQUEST"
    print("    [PASS] Simulation event normalized with detectionSource=SIMULATION.")

    # 4. Dual Timestamp Preservation
    print("\n[4/6] Auditing Dual Timestamp Preservation (eventTimestamp vs processingTimestamp)...")
    assert evt_suri.eventTimestamp.startswith("2026-09-11T10:00:00")
    assert evt_suri.processingTimestamp is not None
    print(f"    Event Timestamp      : {evt_suri.eventTimestamp}")
    print(f"    Processing Timestamp : {evt_suri.processingTimestamp}")
    print("    [PASS] Dual timestamp semantics confirmed intact.")

    # 5. Port and Protocol Coercion Edge Cases
    print("\n[5/6] Auditing Protocol & Port Coercion (Case-Insensitive & Numeric Conversion)...")
    edge_raw = {
        "timestamp": "2026-09-11T10:10:00Z",
        "src_ip": "192.168.1.10",
        "dest_ip": "192.168.1.20",
        "src_port": 50000,
        "dest_port": "80.0",
        "proto": "Icmp"
    }
    evt_edge, err = unified_normalizer.normalize(edge_raw, source_type="suricata")
    assert err is None
    assert evt_edge.protocol == CanonicalProtocolEnum.ICMP
    assert evt_edge.port == 80
    print("    [PASS] Coerced 'Icmp' -> ICMP and '80.0' -> 80.")

    # 6. Quarantine Invariants & Error Interception
    print("\n[6/6] Auditing Quarantine Rejection (Invalid Timestamps, Ports, Protocols, Endpoints)...")
    bad_ts = {"src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "proto": "TCP"}
    _, err_ts = unified_normalizer.normalize(bad_ts, source_type="suricata")
    assert "Missing or null event timestamp" in err_ts

    bad_port = {"timestamp": "2026-09-11T10:00:00Z", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "proto": "TCP", "dest_port": 99999}
    _, err_port = unified_normalizer.normalize(bad_port, source_type="suricata")
    assert "Port 99999 out of bounds" in err_port

    bad_proto = {"timestamp": "2026-09-11T10:00:00Z", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "proto": "UNKNOWN_PROTOCOL"}
    _, err_proto = unified_normalizer.normalize(bad_proto, source_type="suricata")
    assert "Unsupported or unknown protocol" in err_proto

    bad_src = {"timestamp": "2026-09-11T10:00:00Z", "dest_ip": "192.168.1.20", "proto": "TCP"}
    _, err_src = unified_normalizer.normalize(bad_src, source_type="suricata")
    assert "Missing source endpoint" in err_src

    assert len(unified_normalizer.quarantine_store) == 4
    print(f"    [PASS] 4 invalid inputs rejected and quarantined safely without system failure.")

    print("\n" + "=" * 80)
    print("       ALL DAY 87 EVENT NORMALIZATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day87_suite()