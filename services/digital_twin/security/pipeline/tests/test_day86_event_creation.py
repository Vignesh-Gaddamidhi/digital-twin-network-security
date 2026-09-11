import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.security.pipeline.events.network_event import (
    NetworkEvent, NetworkEventTypeEnum, DetectionSourceEnum, EventSeverityEnum, event_id_generator
)
from services.digital_twin.security.pipeline.events.network_event_factory import network_event_factory
from services.digital_twin.security.pipeline.events.network_event_validator import (
    network_event_validator, NetworkEventValidationError
)

def setup_devices():
    device_registry.clear()
    event_id_generator.reset()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    dns = NetworkDeviceModel(id="DNS-01",    hostname="DNS-01",    type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(dns)

def run_day86_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 86: PACKET -> EVENT CREATION AUDIT")
    print("=" * 80 + "\n")

    setup_devices()

    # 1. Event ID Sequential Formatting
    print("[1/6] Auditing Event ID Generation (EVT-XXXXXX)...")
    id1 = event_id_generator.generate()
    id2 = event_id_generator.generate()
    assert id1 == "EVT-000001"
    assert id2 == "EVT-000002"
    print(f"    [PASS] IDs generated sequentially: {id1}, {id2}.")

    # 2. Raw Packet Telemetry -> NetworkEvent
    print("\n[2/6] Converting Raw Packet Telemetry to NetworkEvent...")
    raw_pkt = {
        "timestamp": "2026-09-11T10:00:00Z",
        "src_ip": "192.168.1.10",
        "dest_ip": "192.168.1.20",
        "src_port": 51234,
        "dest_port": 443,
        "protocol": "TCP",
        "bytes": 512,
        "packets": 1
    }
    pkt_evt = network_event_factory.from_packet(raw_pkt)
    print(f"    Event ID        : {pkt_evt.eventId}")
    print(f"    Source (Host)   : {pkt_evt.source}")
    print(f"    Destination     : {pkt_evt.destination}")
    print(f"    Event Type      : {pkt_evt.eventType.value}")
    print(f"    Severity        : {pkt_evt.severity.value}")
    print(f"    DetectionSource : {pkt_evt.detectionSource.value}")

    assert pkt_evt.source == "CLIENT-01"
    assert pkt_evt.destination == "WEB-01"
    assert pkt_evt.eventType == NetworkEventTypeEnum.HTTPS_CONNECTION
    assert pkt_evt.severity == EventSeverityEnum.INFO
    assert pkt_evt.detectionSource == DetectionSourceEnum.PACKET_CAPTURE
    print("    [PASS] Packet telemetry normalized to HTTPS_CONNECTION with INFO severity.")

    # 3. Suricata EVE Alert -> NetworkEvent (Source vs DetectionSource Disambiguation)
    print("\n[3/6] Converting Suricata EVE Alert & Disambiguating Source vs DetectionSource...")
    suri_raw = {
        "timestamp": "2026-09-11T10:00:01Z",
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "src_port": 50000,
        "dest_ip": "192.168.1.20",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": "ET EXPLOIT OpenSSL Heartbleed",
            "severity": 1
        }
    }
    suri_evt = network_event_factory.from_suricata(suri_raw)
    print(f"    source          : {suri_evt.source} (Network entity)")
    print(f"    detectionSource : {suri_evt.detectionSource.value} (Telemetry subsystem)")
    print(f"    severity        : {suri_evt.severity.value} (Calibrated from alert severity 1)")

    assert suri_evt.source == "CLIENT-01"
    assert suri_evt.destination == "WEB-01"
    assert suri_evt.detectionSource == DetectionSourceEnum.SURICATA
    assert suri_evt.source != suri_evt.detectionSource.value
    assert suri_evt.eventType == NetworkEventTypeEnum.IDS_ALERT
    assert suri_evt.severity == EventSeverityEnum.CRITICAL
    assert suri_evt.signature == "ET EXPLOIT OpenSSL Heartbleed"
    print("    [PASS] Verified strict separation of traffic source (CLIENT-01) and detectionSource (SURICATA).")

    # 4. Zeek Protocol Log -> NetworkEvent
    print("\n[4/6] Converting Zeek Connection Log Telemetry...")
    zeek_raw = {
        "ts": 1773121500.0,
        "uid": "ZCONN99",
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 54000,
        "id.resp_h": "192.168.1.53",
        "id.resp_p": 53,
        "proto": "udp",
        "orig_bytes": 64,
        "resp_bytes": 128
    }
    zeek_evt = network_event_factory.from_zeek(zeek_raw, stream_hint="dns")
    assert zeek_evt.source == "CLIENT-01"
    assert zeek_evt.destination == "DNS-01"
    assert zeek_evt.destinationPort == 53
    assert zeek_evt.eventType == NetworkEventTypeEnum.DNS_QUERY
    assert zeek_evt.detectionSource == DetectionSourceEnum.ZEEK
    assert zeek_evt.severity == EventSeverityEnum.INFO
    assert zeek_evt.bytes == 192
    print("    [PASS] Zeek telemetry mapped to DNS_QUERY with INFO severity and aggregated byte counters.")

    # 5. Twin Simulation Event -> NetworkEvent
    print("\n[5/6] Converting Digital Twin Synthetic Traffic Event...")
    sim_raw = {
        "simulationId": "sim-run-1234",
        "timestamp": "2026-09-11T10:00:03Z",
        "sourceDevice": "CLIENT-01",
        "destinationDevice": "WEB-01",
        "sourcePort": 55000,
        "destinationPort": 22,
        "protocol": "TCP",
        "bytes": 256,
        "packets": 1
    }
    sim_evt = network_event_factory.from_simulation(sim_raw)
    assert sim_evt.source == "CLIENT-01"
    assert sim_evt.destination == "WEB-01"
    assert sim_evt.eventType == NetworkEventTypeEnum.SSH_CONNECTION
    assert sim_evt.detectionSource == DetectionSourceEnum.SIMULATION
    assert sim_evt.severity == EventSeverityEnum.INFO
    print("    [PASS] Simulation event mapped to SSH_CONNECTION with SIMULATION detectionSource.")

    # 6. Event Validation Guardrails
    print("\n[6/6] Auditing Event Validation Invariants & Error Interception...")
    invalid_port_evt = NetworkEvent(
        eventId="EVT-ERR-001",
        source="CLIENT-01",
        destination="WEB-01",
        destinationPort=99999,  # Illegal port
        eventType=NetworkEventTypeEnum.NETWORK_CONNECTION,
        detectionSource=DetectionSourceEnum.PACKET_CAPTURE
    )
    is_valid, err = network_event_validator.validate(invalid_port_evt)
    assert is_valid is False
    assert "Invalid destinationPort" in err
    print(f"    [PASS] Invalid port rejected: {err}")

    invalid_src_evt = NetworkEvent(
        eventId="EVT-ERR-002",
        source="",  # Missing source
        destination="WEB-01",
        destinationPort=80,
        eventType=NetworkEventTypeEnum.NETWORK_CONNECTION,
        detectionSource=DetectionSourceEnum.PACKET_CAPTURE
    )
    is_valid, err = network_event_validator.validate(invalid_src_evt)
    assert is_valid is False
    assert "Missing mandatory field 'source'" in err
    print(f"    [PASS] Missing source rejected: {err}")

    print("\n" + "=" * 80)
    print("       ALL DAY 86 PACKET -> EVENT CREATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day86_suite()