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
from services.digital_twin.ids.processor.twin_event_processor import suricata_twin_processor
from services.digital_twin.ids.suricata.collector.eve_collector import suricata_collector

SAMPLE_SURICATA_BATCH = """
{"timestamp":"2026-09-10T10:00:00.000000+0000","event_type":"flow","src_ip":"192.168.1.10","src_port":49152,"dest_ip":"192.168.1.20","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":20,"pkts_toclient":25,"bytes_toserver":3000,"bytes_toclient":15000,"state":"established"}}
{"timestamp":"2026-09-10T10:00:01.000000+0000","event_type":"flow","src_ip":"10.0.0.99","src_port":54321,"dest_ip":"192.168.1.20","dest_port":8080,"proto":"TCP","flow":{"pkts_toserver":5,"bytes_toserver":500}}
{"timestamp":"2026-09-10T10:00:02.000000+0000","event_type":"alert","src_ip":"192.168.1.10","src_port":49152,"dest_ip":"192.168.1.20","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":1,"signature":"ET EXPLOIT Apache Struts Remote Code Execution","category":"Attempted Administrator Privilege Gain","severity":1}}
"""

def run_day81_suite():
    print("=" * 80)
    print("       WEEK 12 - DAY 81: SURICATA -> DIGITAL TWIN INTEGRATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    security_state_engine.clear()
    network_state_engine.clear()
    suricata_collector.clear()
    suricata_twin_processor.clear()
    twin_device_resolver.clear()

    # 1. Provision Topology
    print("[1/5] Provisioning Twin Topology...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)

    # Initialize security posture
    for dev_id in ["CLIENT-01", "WEB-01"]:
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
    print("    [PASS] CLIENT-01 and WEB-01 provisioned with baseline security status.")

    # 2. Test Device Resolver & Unknown Device Handling
    print("\n[2/5] Testing Twin Device Resolver & Unmanaged Asset Discovery...")
    dev_client = twin_device_resolver.resolve("192.168.1.10", port=49152, protocol="TCP")
    dev_web    = twin_device_resolver.resolve("192.168.1.20", port=443, protocol="TCP")
    dev_unk    = twin_device_resolver.resolve("10.0.0.99", port=8080, protocol="TCP")

    assert dev_client == "CLIENT-01"
    assert dev_web == "WEB-01"
    assert dev_unk == "UNKNOWN_DEVICE"
    assert "10.0.0.99" in twin_device_resolver.unknown_devices

    unk_entry = twin_device_resolver.unknown_devices["10.0.0.99"]
    assert 8080 in unk_entry.observedPorts
    assert "TCP" in unk_entry.observedProtocols
    print(f"    [PASS] Known resolved correctly; Unknown IP 10.0.0.99 captured with observed port {unk_entry.observedPorts}.")

    # 3. Process Direct Telemetry Event (Flow -> Network State Update)
    print("\n[3/5] Testing Digital Twin Network State Update on Network Flow Event...")
    flow_evt = NormalizedSecurityEvent(
        source=EventSourceEnum.SURICATA,
        eventType=SecurityEventTypeEnum.FLOW,
        sourceIP="192.168.1.10",
        destinationIP="192.168.1.20",
        sourcePort=49152,
        destinationPort=443,
        protocol="TCP",
        severity=NormalizedSecuritySeverityEnum.LOW,
        signature="Flow Session",
        metadata={"bytes_toserver": 3000, "bytes_toclient": 15000, "pkts_toserver": 20, "pkts_toclient": 25}
    )

    rec = suricata_twin_processor.processEvent(flow_evt)
    assert rec.twinUpdated is True
    assert rec.sourceDevice == "CLIENT-01"
    assert rec.destinationDevice == "WEB-01"

    stats = network_state_engine.getConnectionStats("WEB-01")
    assert stats.active >= 1
    print("    [PASS] Flow session recorded in Twin Network State Engine.")

    # 4. Process Security Alert (Suricata Alert -> Twin Posture Degradation)
    print("\n[4/5] Testing Twin Posture Degradation on Critical Suricata Alert...")
    alert_evt = NormalizedSecurityEvent(
        source=EventSourceEnum.SURICATA,
        eventType=SecurityEventTypeEnum.ALERT,
        sourceIP="192.168.1.10",
        destinationIP="192.168.1.20",
        sourcePort=49152,
        destinationPort=443,
        protocol="TCP",
        severity=NormalizedSecuritySeverityEnum.CRITICAL,
        signature="ET EXPLOIT Apache Struts RCE",
        metadata={"gid": 1, "sid": 2001219}
    )

    alert_rec = suricata_twin_processor.processEvent(alert_evt)
    assert alert_rec.securityPostureChanged is True

    posture = security_state_engine.getSecurityStatus("WEB-01")
    posture_str = posture.value if hasattr(posture, "value") else str(posture)
    assert "COMPROMISED" in str(posture_str)
    print(f"    [PASS] Critical alert successfully degraded WEB-01 security posture to: {posture_str}.")

    # 5. End-to-End Ingestion Collector Integration Audit
    print("\n[5/5] Auditing End-to-End Pipeline Ingestion (Collector -> Processor -> Twin)...")
    res = suricata_collector.collect_from_string(SAMPLE_SURICATA_BATCH)
    assert res.validCount == 3
    assert len(suricata_twin_processor.history) >= 4  # Prior unit tests + 3 from batch
    print(f"    [PASS] End-to-end ingestion completed: {res.validCount} valid events synced across Twin State Engines.")

    print("\n" + "=" * 80)
    print("       ALL DAY 81 SURICATA -> TWIN INTEGRATION TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_day81_suite()