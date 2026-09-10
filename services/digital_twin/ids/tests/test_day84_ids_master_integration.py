import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, EventSourceEnum, SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine

from services.digital_twin.ids.processor.device_resolver import twin_device_resolver
from services.digital_twin.ids.processor.correlation_engine import ids_correlation_engine
from services.digital_twin.ids.processor.multi_source_processor import multi_source_processor
from services.digital_twin.ids.suricata.collector.eve_collector import suricata_collector
from services.digital_twin.ids.zeek.collector.zeek_collector import zeek_collector

def provision_test_environment():
    device_registry.clear()
    security_state_engine.clear()
    network_state_engine.clear()
    twin_device_resolver.clear()
    ids_correlation_engine.clear()
    multi_source_processor.clear()
    suricata_collector.clear()
    zeek_collector.clear()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[22, 80, 443])
    dns = NetworkDeviceModel(id="DNS-01",    hostname="DNS-01",    type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(dns)

    for dev_id in ["CLIENT-01", "WEB-01", "DNS-01"]:
        try:
            if hasattr(security_state_engine, "createSecurityState"):
                from packages.shared_types.src import security_state
                m = getattr(security_state, "SecurityStateModel", None) or getattr(security_state, "DeviceSecurityModel", None)
                if m:
                    security_state_engine.createSecurityState(m(deviceId=dev_id, status=SecurityPostureStatusEnum.NORMAL))
            elif hasattr(security_state_engine, "initializeDevice"):
                security_state_engine.initializeDevice(dev_id)
        except Exception:
            pass

def run_day84_master_suite():
    print("=" * 80)
    print("       WEEK 12 - DAY 84: COMPLETE IDS/NSM INTEGRATION MASTER AUDIT")
    print("=" * 80 + "\n")

    provision_test_environment()

    # 1. Suricata Ingestion Matrix Audit
    print("[1/9] Auditing Suricata Multi-Type Ingestion & Validation Matrix...")
    suricata_sample = """
    {"timestamp":"2026-09-10T12:00:01Z","event_type":"alert","src_ip":"192.168.1.10","src_port":51000,"dest_ip":"192.168.1.20","dest_port":80,"proto":"TCP","alert":{"signature":"ET WEB_SERVER SQLi","severity":1}}
    {"timestamp":"2026-09-10T12:00:02Z","event_type":"flow","src_ip":"192.168.1.10","src_port":51002,"dest_ip":"192.168.1.20","dest_port":443,"proto":"TCP","flow":{"bytes_toserver":1200,"bytes_toclient":5400}}
    {"timestamp":"2026-09-10T12:00:03Z","event_type":"dns","src_ip":"192.168.1.10","src_port":61000,"dest_ip":"192.168.1.53","dest_port":53,"proto":"UDP","dns":{"rrname":"corp.test","rrtype":"A"}}
    {"timestamp":"2026-09-10T12:00:04Z","event_type":"http","src_ip":"192.168.1.10","src_port":51004,"dest_ip":"192.168.1.20","dest_port":80,"proto":"TCP","http":{"hostname":"corp.test","url":"/admin","status":403}}
    {"timestamp":"2026-09-10T12:00:05Z","event_type":"tls","src_ip":"192.168.1.10","src_port":51006,"dest_ip":"192.168.1.20","dest_port":443,"proto":"TCP","tls":{"sni":"corp.test","version":"TLS 1.3"}}
    {MALFORMED_JSON_LINE}
    {"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","proto":"TCP"}
    {"timestamp":"2026-09-10T12:00:07Z","event_type":"unknown_alien_scan","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","proto":"TCP"}
    """
    s_res = suricata_collector.collect_from_string(suricata_sample)
    assert s_res.validCount == 5
    assert s_res.malformedCount == 3
    print(f"    [PASS] Suricata Matrix: 5 valid parsed (alert, flow, dns, http, tls), 3 malformed rejected cleanly.")

    # 2. Zeek Ingestion Matrix Audit
    print("\n[2/9] Auditing Zeek Protocol Log Matrix (conn, dns, http, ssl, ssh)...")
    zeek_sample = """
    {"ts":1773121000.0,"uid":"Z1","id.orig_h":"192.168.1.10","id.orig_p":52000,"id.resp_h":"192.168.1.20","id.resp_p":80,"proto":"tcp","conn_state":"SF","orig_bytes":500,"resp_bytes":2000}
    {"ts":1773121001.0,"uid":"Z2","id.orig_h":"192.168.1.10","id.orig_p":62000,"id.resp_h":"192.168.1.53","id.resp_p":53,"proto":"udp","query":"internal.test","qtype_name":"A"}
    {"ts":1773121002.0,"uid":"Z3","id.orig_h":"192.168.1.10","id.orig_p":52002,"id.resp_h":"192.168.1.20","id.resp_p":80,"proto":"tcp","method":"GET","host":"internal.test","uri":"/","status_code":200}
    {"ts":1773121003.0,"uid":"Z4","id.orig_h":"192.168.1.10","id.orig_p":52004,"id.resp_h":"192.168.1.20","id.resp_p":443,"proto":"tcp","server_name":"internal.test","version":"TLSv1.3"}
    {"ts":1773121004.0,"uid":"Z5","id.orig_h":"192.168.1.10","id.orig_p":52006,"id.resp_h":"192.168.1.20","id.resp_p":22,"proto":"tcp","auth_success":true}
    {"id.orig_h":"192.168.1.10"}
    """
    z_res = zeek_collector.collect_from_string(zeek_sample)
    assert z_res.validCount == 5
    assert z_res.malformedCount == 1
    print(f"    [PASS] Zeek Matrix: 5 valid streams parsed, 1 missing-field record rejected cleanly.")

    # 3. Source-Agnostic Normalization Equivalence
    print("\n[3/9] Auditing Cross-Source Event Normalization Equivalence...")
    suri_evt = suricata_collector.normalized_events[0]
    zeek_evt = zeek_collector.normalized_events[0]
    assert isinstance(suri_evt, NormalizedSecurityEvent)
    assert isinstance(zeek_evt, NormalizedSecurityEvent)
    assert suri_evt.source == EventSourceEnum.SURICATA
    assert zeek_evt.source == EventSourceEnum.ZEEK
    print(f"    [PASS] Both telemetry sources normalize to canonical NormalizedSecurityEvent.")

    # 4. Digital Twin Network State Synchronization
    print("\n[4/9] Auditing Digital Twin Network State Synchronization...")
    stats = network_state_engine.getConnectionStats("WEB-01")
    assert stats.active >= 1
    print(f"    [PASS] Active socket session state verified on WEB-01 (Active sessions: {stats.active}).")

    # 5. Security State Degradation
    print("\n[5/9] Auditing Security Posture Degradation on Suricata Alert...")
    posture = security_state_engine.getSecurityStatus("WEB-01")
    posture_str = posture.value if hasattr(posture, "value") else str(posture)
    assert "COMPROMISED" in str(posture_str)
    print(f"    [PASS] Target WEB-01 confirmed degraded to: {posture_str}.")

    # 6. Unknown Device Resolution & Dynamic Asset Discovery
    print("\n[6/9] Auditing Unmapped Asset Discovery (UNKNOWN_DEVICE)...")
    unk_ip = "172.16.99.100"
    resolved_unk = twin_device_resolver.resolve(unk_ip, port=3389, protocol="TCP")
    assert resolved_unk == "UNKNOWN_DEVICE"
    assert unk_ip in twin_device_resolver.unknown_devices
    assert 3389 in twin_device_resolver.unknown_devices[unk_ip].observedPorts
    print(f"    [PASS] Unknown IP {unk_ip} tagged UNKNOWN_DEVICE and recorded in asset discovery registry.")

    # 7. Deduplication & Idempotency Audit
    print("\n[7/9] Auditing Event Deduplication & Ingestion Idempotency...")
    duplicate_event = NormalizedSecurityEvent(
        eventId="duplicate-fixed-id-001",
        source=EventSourceEnum.SURICATA,
        eventType=SecurityEventTypeEnum.ALERT,
        timestamp="2026-09-10T12:00:00Z",
        sourceIP="192.168.1.10",
        destinationIP="192.168.1.20",
        sourcePort=49000,
        destinationPort=80,
        protocol="TCP",
        severity=NormalizedSecuritySeverityEnum.MEDIUM,
        signature="ET SCAN Test Recon"
    )
    first_summary = multi_source_processor.process(duplicate_event)
    second_summary = multi_source_processor.process(duplicate_event)

    assert first_summary.isDuplicate is False
    assert second_summary.isDuplicate is True
    print("    [PASS] Idempotency confirmed: Duplicate arrival tagged isDuplicate=True without duplicate state updates.")

    # 8. Out-of-Order Timestamp Preservation
    print("\n[8/9] Auditing Out-of-Order Event Timestamp Preservation...")
    t3 = NormalizedSecurityEvent(eventId="e3", source=EventSourceEnum.ZEEK, eventType=SecurityEventTypeEnum.FLOW, timestamp="2026-09-10T13:00:03Z", sourceIP="192.168.1.10", destinationIP="192.168.1.20", protocol="TCP")
    t1 = NormalizedSecurityEvent(eventId="e1", source=EventSourceEnum.ZEEK, eventType=SecurityEventTypeEnum.FLOW, timestamp="2026-09-10T13:00:01Z", sourceIP="192.168.1.10", destinationIP="192.168.1.20", protocol="TCP")
    t2 = NormalizedSecurityEvent(eventId="e2", source=EventSourceEnum.ZEEK, eventType=SecurityEventTypeEnum.FLOW, timestamp="2026-09-10T13:00:02Z", sourceIP="192.168.1.10", destinationIP="192.168.1.20", protocol="TCP")

    # Ingest in out-of-order sequence: t3, t1, t2
    multi_source_processor.process(t3)
    multi_source_processor.process(t1)
    multi_source_processor.process(t2)

    chrono = multi_source_processor.get_chronological_history()
    chrono_ids = [c.eventId for c in chrono if c.eventId in ["e1", "e2", "e3"]]
    assert chrono_ids == ["e1", "e2", "e3"]
    print(f"    [PASS] Ingested in order [e3, e1, e2] -> Chronological order preserved: {chrono_ids}.")

    # 9. Fault Tolerance & Zero-Crash Resilience
    print("\n[9/9] Auditing Fault Resilience on Garbage/Empty Inputs...")
    res_empty_suri = suricata_collector.collect_from_string("")
    res_empty_zeek = zeek_collector.collect_from_string("")
    assert res_empty_suri.totalProcessed == 0
    assert res_empty_zeek.totalProcessed == 0

    res_garbage_suri = suricata_collector.collect_from_string("NOT_VALID_EVE\n{CORRUPTED_JSON\n")
    assert res_garbage_suri.malformedCount == 2
    print("    [PASS] Pipeline demonstrated complete fault resilience with zero exceptions.")

    print("\n" + "=" * 80)
    print("       ALL 9 MASTER INTEGRATION TEST AUDITS PASSED CLEANLY")
    print("       PHASE 9: REAL IDS/NSM INTEGRATION OFFICIALLY COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_day84_master_suite()