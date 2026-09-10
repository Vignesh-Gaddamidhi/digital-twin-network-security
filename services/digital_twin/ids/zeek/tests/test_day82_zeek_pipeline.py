import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.normalized_security_event import (
    EventSourceEnum, SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.ids.zeek.collector.zeek_collector import zeek_collector

# Sample 1: Zeek JSON multi-stream records
SAMPLE_ZEEK_JSON = """
{"ts":1773120000.0,"uid":"C12345","id.orig_h":"192.168.1.10","id.orig_p":54120,"id.resp_h":"192.168.1.20","id.resp_p":80,"proto":"tcp","conn_state":"SF","duration":2.45,"orig_bytes":1250,"resp_bytes":8420}
{"ts":1773120001.0,"uid":"D67890","id.orig_h":"192.168.1.10","id.orig_p":61000,"id.resp_h":"192.168.1.53","id.resp_p":53,"proto":"udp","query":"service.test","qtype_name":"A","rcode_name":"NOERROR"}
{"ts":1773120002.0,"uid":"H11223","id.orig_h":"192.168.1.10","id.orig_p":54122,"id.resp_h":"192.168.1.20","id.resp_p":80,"proto":"tcp","method":"GET","host":"corp.test","uri":"/api/v1/status","status_code":200}
{"ts":1773120003.0,"uid":"S44556","id.orig_h":"192.168.1.10","id.orig_p":54124,"id.resp_h":"192.168.1.20","id.resp_p":443,"proto":"tcp","server_name":"secure.corp.test","version":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384"}
{"ts":1773120004.0,"uid":"X99887","id.orig_h":"192.168.1.10","id.orig_p":54126,"id.resp_h":"192.168.1.22","id.resp_p":22,"proto":"tcp","auth_success":true,"direction":"INBOUND"}
"""

# Sample 2: Zeek Tab-Separated Values (TSV) stream with #fields header
SAMPLE_ZEEK_TSV = """#separator \x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state
1773120010.0\tC99901\t192.168.1.10\t45000\t192.168.1.20\t443\ttcp\tssl\t1.12\t800\t3200\tSF
1773120011.0\tC99902\t192.168.1.10\t45002\t192.168.1.20\t443\ttcp\tssl\t-\t-\t-\tS0
"""

# Sample 3: Malformed lines
SAMPLE_ZEEK_MALFORMED = """
{"id.orig_h":"192.168.1.10"}
{"id.orig_h":"INVALID_IP","id.resp_h":"192.168.1.20"}
{"id.orig_h":"192.168.1.10","id.resp_h":"NOT_AN_IP"}
"""

def run_day82_zeek_suite():
    print("=" * 80)
    print("       WEEK 12 - DAY 82: ZEEK NSM PROTOCOL LOG INGESTION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    network_state_engine.clear()
    zeek_collector.clear()

    # 1. Provision Topology Hosts in Twin
    print("[1/5] Provisioning Target Devices in Digital Twin Registry...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    srv = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    dns = NetworkDeviceModel(id="DNS-01",    hostname="DNS-01",    type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(srv)
    device_registry.createDevice(dns)
    print("    [PASS] CLIENT-01, WEB-01, SERVER-01, and DNS-01 provisioned.")

    # 2. Ingest Zeek Streaming JSON across conn, dns, http, ssl, ssh
    print("\n[2/5] Ingesting Zeek Streaming JSON (conn, dns, http, ssl, ssh)...")
    json_res = zeek_collector.collect_from_string(SAMPLE_ZEEK_JSON)

    print(f"    Total Processed : {json_res.totalProcessed}")
    print(f"    Valid Events    : {json_res.validCount}")
    print(f"    Malformed Events: {json_res.malformedCount}")

    assert json_res.totalProcessed == 5
    assert json_res.validCount == 5
    assert json_res.malformedCount == 0
    assert len(zeek_collector.normalized_events) == 5

    evts = zeek_collector.normalized_events
    conn_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.FLOW)
    dns_evt  = next(e for e in evts if e.eventType == SecurityEventTypeEnum.DNS)
    http_evt = next(e for e in evts if e.eventType == SecurityEventTypeEnum.HTTP)
    tls_evt  = next(e for e in evts if e.eventType == SecurityEventTypeEnum.TLS)
    ssh_evt  = next(e for e in evts if e.eventType == SecurityEventTypeEnum.SSH)

    assert conn_evt.source == EventSourceEnum.ZEEK
    assert conn_evt.metadata["conn_state"] == "SF"
    assert conn_evt.sourceDevice == "CLIENT-01"
    assert conn_evt.destinationDevice == "WEB-01"

    assert dns_evt.metadata["query"] == "service.test"
    assert dns_evt.destinationDevice == "DNS-01"

    assert http_evt.metadata["method"] == "GET"
    assert http_evt.metadata["status_code"] == 200

    assert tls_evt.metadata["server_name"] == "secure.corp.test"
    assert ssh_evt.metadata["auth_success"] is True
    print("    [PASS] Zeek JSON multi-protocol records normalized with canonical schema.")

    # 3. Ingest Zeek Standard TSV Log
    print("\n[3/5] Ingesting Standard Zeek #fields TSV Log Format...")
    tsv_res = zeek_collector.collect_from_string(SAMPLE_ZEEK_TSV, stream_hint="conn")
    print(f"    TSV Processed : {tsv_res.totalProcessed}")
    print(f"    TSV Valid     : {tsv_res.validCount}")

    assert tsv_res.validCount == 2
    tsv_evts = zeek_collector.normalized_events[5:]
    assert tsv_evts[0].metadata["conn_state"] == "SF"
    assert tsv_evts[0].metadata["orig_bytes"] == 800
    assert tsv_evts[1].metadata["conn_state"] == "S0"
    print("    [PASS] Zeek TSV parsing verified with proper '-' null-handling.")

    # 4. Dead-Letter Error Queue Invariant
    print("\n[4/5] Auditing Dead-Letter Error Queue on Malformed Records...")
    mal_res = zeek_collector.collect_from_string(SAMPLE_ZEEK_MALFORMED)
    assert mal_res.validCount == 0
    assert mal_res.malformedCount == 3
    assert len(zeek_collector.malformed_queue) == 3

    errors = [m.errorReason for m in zeek_collector.malformed_queue]
    assert any("Missing responder/destination IP address" in e for e in errors)
    assert any("Invalid source IP address format" in e for e in errors)
    assert any("Invalid destination IP address format" in e for e in errors)
    print("    [PASS] Zeek dead-letter queue caught missing and malformed IP records.")

    # 5. Digital Twin Telemetry State Feedback
    print("\n[5/5] Auditing Digital Twin Network State Synchronization...")
    stats = network_state_engine.getConnectionStats("WEB-01")
    assert stats.active >= 1
    print(f"    Active Sessions on WEB-01: {stats.active}")
    print("    [PASS] Zeek connection flows registered active sessions in Twin Network State Engine.")

    print("\n" + "=" * 80)
    print("       ALL DAY 82 ZEEK PROTOCOL LOG PIPELINE TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_day82_zeek_suite()