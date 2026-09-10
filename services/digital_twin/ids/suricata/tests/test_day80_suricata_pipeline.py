import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.normalized_security_event import (
    EventSourceEnum, SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)
from packages.shared_types.src.security_state import SecurityPostureStatusEnum

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.ids.processor.ids_processor import ids_processor
from services.digital_twin.ids.suricata.collector.eve_collector import suricata_collector

# Valid EVE records covering the 5 primary categories
VALID_EVE_DATA = """
{"timestamp":"2026-09-09T05:00:01.000000+0000","event_type":"alert","src_ip":"192.168.1.10","src_port":54321,"dest_ip":"192.168.1.20","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":2,"signature":"ET SCAN Potential SSH Brute Force","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-09-09T05:00:02.000000+0000","event_type":"flow","src_ip":"192.168.1.10","src_port":44120,"dest_ip":"192.168.1.20","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":12,"pkts_toclient":10,"bytes_toserver":4500,"bytes_toclient":18000,"state":"closed"}}
{"timestamp":"2026-09-09T05:00:03.000000+0000","event_type":"dns","src_ip":"192.168.1.10","src_port":61000,"dest_ip":"192.168.1.53","dest_port":53,"proto":"UDP","dns":{"type":"query","id":1234,"rrname":"service.internal.test","rrtype":"A","tx_id":0}}
{"timestamp":"2026-09-09T05:00:04.000000+0000","event_type":"http","src_ip":"192.168.1.10","src_port":50000,"dest_ip":"192.168.1.20","dest_port":80,"proto":"TCP","http":{"hostname":"corp.internal.test","url":"/login","http_method":"POST","status":401,"http_user_agent":"Mozilla/5.0"}}
{"timestamp":"2026-09-09T05:00:05.000000+0000","event_type":"tls","src_ip":"192.168.1.10","src_port":50002,"dest_ip":"192.168.1.20","dest_port":443,"proto":"TCP","tls":{"sni":"secure.corp.internal.test","subject":"CN=secure.corp.internal.test","version":"TLS 1.3"}}
"""

# Invalid / Malformed records
MALFORMED_EVE_DATA = """
{NOT_VALID_JSON_AT_ALL}
{"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","proto":"TCP"}
{"timestamp":"2026-09-09T05:00:01Z","event_type":"alert","dest_ip":"192.168.1.20","proto":"TCP"}
{"timestamp":"2026-09-09T05:00:01Z","event_type":"alert","src_ip":"192.168.1.10","dest_ip":"NOT_AN_IP","proto":"TCP"}
{"timestamp":"2026-09-09T05:00:01Z","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","proto":"TCP"}
{"timestamp":"2026-09-09T05:00:01Z","event_type":"space_aliens_detected","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","proto":"TCP"}
{"timestamp":"2026-09-09T05:00:01Z","event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","proto":"TCP","alert":"this_should_be_a_dict_not_a_string"}
"""

def run_day80_pipeline_suite():
    print("=" * 80)
    print("       WEEK 12 - DAY 80: SURICATA EVE INGESTION PIPELINE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    security_state_engine.clear()
    ids_processor.clear()
    suricata_collector.clear()

    # 1. Provision Digital Twin Network
    print("[1/5] Provisioning Twin Topology...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[22, 80, 443])
    dns = NetworkDeviceModel(id="DNS-01",    hostname="DNS-01",    type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(dns)
    print("    [PASS] Provisioned CLIENT-01, WEB-01, and DNS-01.")

    # 2. Ingest Valid Multi-Category EVE Stream (Alert, Flow, DNS, HTTP, TLS)
    print("\n[2/5] Ingesting Valid EVE Stream Across 5 Categories...")
    res = suricata_collector.collect_from_string(VALID_EVE_DATA)
    print(f"    Total Processed : {res.totalProcessed}")
    print(f"    Valid Count     : {res.validCount}")
    print(f"    Malformed Count : {res.malformedCount}")

    assert res.totalProcessed == 5
    assert res.validCount == 5
    assert res.malformedCount == 0
    assert len(suricata_collector.normalized_events) == 5
    print("    [PASS] Successfully parsed and normalized all 5 valid categories.")

    # 3. Verify Category-Specific Metadata Extraction
    print("\n[3/5] Auditing Category-Specific Field Extraction...")
    evts = suricata_collector.normalized_events

    # Alert verification
    alert_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.ALERT)
    assert alert_evt.metadata["sid"] == 2001219
    assert alert_evt.severity == NormalizedSecuritySeverityEnum.HIGH
    assert alert_evt.destinationDevice == "WEB-01"
    print("    [PASS] Alert: SID=2001219, Severity=HIGH, Target=WEB-01.")

    # Flow verification
    flow_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.FLOW)
    assert flow_evt.metadata["bytes_toserver"] == 4500
    assert flow_evt.metadata["bytes_toclient"] == 18000
    assert flow_evt.protocol == "TCP"
    print("    [PASS] Flow: BytesToServer=4500, BytesToClient=18000.")

    # DNS verification
    dns_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.DNS)
    assert dns_evt.metadata["rrname"] == "service.internal.test"
    assert dns_evt.metadata["rrtype"] == "A"
    assert dns_evt.destinationDevice == "DNS-01"
    print("    [PASS] DNS: Query=service.internal.test, Type=A, Target=DNS-01.")

    # HTTP verification
    http_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.HTTP)
    assert http_evt.metadata["hostname"] == "corp.internal.test"
    assert http_evt.metadata["status"] == 401
    assert http_evt.metadata["http_method"] == "POST"
    print("    [PASS] HTTP: Host=corp.internal.test, Method=POST, Status=401.")

    # TLS verification
    tls_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.TLS)
    assert tls_evt.metadata["sni"] == "secure.corp.internal.test"
    assert tls_evt.metadata["version"] == "TLS 1.3"
    print("    [PASS] TLS: SNI=secure.corp.internal.test, Version=TLS 1.3.")

    # 4. Dead-Letter Error Queue Invariant Audit
    print("\n[4/5] Auditing Dead-Letter Error Queue (Malformed Telemetry Rejection)...")
    err_res = suricata_collector.collect_from_string(MALFORMED_EVE_DATA)
    print(f"    Malformed Records Ingested : {err_res.malformedCount}")
    print(f"    Valid Records Ingested     : {err_res.validCount}")

    assert err_res.validCount == 0
    assert err_res.malformedCount == 7
    assert len(suricata_collector.malformed_queue) == 7

    reasons = [m.errorReason for m in err_res.malformedRecords]
    print(f"    Sample Rejection Reasons:")
    for r in reasons[:4]:
        print(f"      - {r}")

    # Verify specific error types captured
    assert any("Invalid JSON" in r for r in reasons)
    assert any("Missing required field 'timestamp'" in r for r in reasons)
    assert any("Missing required field 'src_ip'" in r for r in reasons)
    assert any("Invalid destination IP address format" in r for r in reasons)
    assert any("Missing required field 'event_type'" in r for r in reasons)
    assert any("Unknown or unsupported event_type" in r for r in reasons)
    assert any("must be a dictionary" in r for r in reasons)
    print("    [PASS] Dead-letter queue caught all 7 malformed records without silent dropping.")

    # 5. Twin Posture Verification
    print("\n[5/5] Auditing Digital Twin Security Posture Update...")
    posture = security_state_engine.getSecurityStatus("WEB-01")
    posture_val = posture.value if hasattr(posture, "value") else str(posture)
    print(f"    WEB-01 Posture State: {posture_val}")
    assert "COMPROMISED" in str(posture_val)
    print("    [PASS] Digital Twin reflected Suricata SSH brute-force alert.")

    print("\n" + "=" * 80)
    print("       ALL DAY 80 SURICATA EVE PIPELINE TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_day80_pipeline_suite()