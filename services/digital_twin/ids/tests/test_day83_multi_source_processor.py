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
from services.digital_twin.ids.processor.correlation_engine import ids_correlation_engine
from services.digital_twin.ids.processor.multi_source_processor import multi_source_processor
from services.digital_twin.ids.suricata.collector.eve_collector import suricata_collector
from services.digital_twin.ids.zeek.collector.zeek_collector import zeek_collector

def run_day83_suite():
    print("=" * 80)
    print("       WEEK 12 - DAY 83: MULTI-SOURCE PROCESSOR & CORRELATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    security_state_engine.clear()
    network_state_engine.clear()
    multi_source_processor.clear()
    suricata_collector.clear()
    zeek_collector.clear()

    # 1. Provision Topology
    print("[1/5] Provisioning Target Devices...")
    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)

    # Initialize baseline security records
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
    print("    [PASS] Registered CLIENT-01 and WEB-01.")

    # 2. Feed Zeek Conn Telemetry
    print("\n[2/5] Ingesting Zeek Flow Connection Record (192.168.1.10:49152 -> 192.168.1.20:80)...")
    zeek_flow = NormalizedSecurityEvent(
        source=EventSourceEnum.ZEEK,
        eventType=SecurityEventTypeEnum.FLOW,
        timestamp="2026-09-10T12:00:00.000000+00:00",
        sourceIP="192.168.1.10",
        destinationIP="192.168.1.20",
        sourcePort=49152,
        destinationPort=80,
        protocol="TCP",
        bytes=4200,
        packets=18,
        application="HTTP",
        severity=NormalizedSecuritySeverityEnum.LOW,
        signature="Zeek Conn SF"
    )
    sum_z = multi_source_processor.process(zeek_flow)
    assert sum_z.source == "ZEEK"
    assert sum_z.sourceDevice == "CLIENT-01"
    assert sum_z.destinationDevice == "WEB-01"
    assert sum_z.hasAlertCorrelated is False

    ctx_mid = ids_correlation_engine.get_context(sum_z.correlationKey)
    assert ctx_mid is not None
    assert ctx_mid.eventCount == 1
    assert ctx_mid.totalBytes == 4200
    assert EventSourceEnum.ZEEK in ctx_mid.sourcesInvolved
    print(f"    [PASS] Zeek flow established correlation context: {ctx_mid.correlationKey} (Bytes: {ctx_mid.totalBytes}).")

    # 3. Feed Suricata Alert for Identical 5-Tuple Within 3 Seconds
    print("\n[3/5] Ingesting Suricata Alert for Same 5-Tuple (Timestamp + 3s)...")
    suri_alert = NormalizedSecurityEvent(
        source=EventSourceEnum.SURICATA,
        eventType=SecurityEventTypeEnum.ALERT,
        timestamp="2026-09-10T12:00:03.000000+00:00",
        sourceIP="192.168.1.10",
        destinationIP="192.168.1.20",
        sourcePort=49152,
        destinationPort=80,
        protocol="TCP",
        bytes=500,
        packets=2,
        application="HTTP",
        severity=NormalizedSecuritySeverityEnum.HIGH,
        signature="ET WEB_SERVER SQL Injection Attempt",
        metadata={"sid": 2000010}
    )
    sum_s = multi_source_processor.process(suri_alert)

    # 4. Verify 5-Tuple Correlation Fusion
    print("\n[4/5] Auditing Multi-Source Correlation Fusion...")
    assert sum_s.correlationKey == sum_z.correlationKey
    assert "SURICATA" in sum_s.sourcesCorrelated
    assert "ZEEK" in sum_s.sourcesCorrelated
    assert sum_s.hasAlertCorrelated is True
    assert sum_s.securityStatusTarget == "COMPROMISED"

    ctx_fused = ids_correlation_engine.get_context(sum_s.correlationKey)
    assert ctx_fused.eventCount == 2
    assert ctx_fused.totalBytes == 4700  # 4200 (Zeek) + 500 (Suricata)
    assert ctx_fused.totalPackets == 20
    assert ctx_fused.highestSeverity == NormalizedSecuritySeverityEnum.HIGH
    assert "ET WEB_SERVER SQL Injection Attempt" in ctx_fused.alertSignatures
    assert len(ctx_fused.sourcesInvolved) == 2
    print("    [PASS] Correlated Context successfully fused SURICATA alert with ZEEK flow telemetry.")
    print(f"           - Sources Involved: {[s.value for s in ctx_fused.sourcesInvolved]}")
    print(f"           - Aggregated Bytes: {ctx_fused.totalBytes}B over {ctx_fused.totalPackets} packets")
    print(f"           - Alerts Linked   : {ctx_fused.alertSignatures}")

    # 5. Verify Digital Twin Synchronization
    print("\n[5/5] Auditing Twin Security Posture & State Degradation...")
    posture = security_state_engine.getSecurityStatus("WEB-01")
    posture_str = posture.value if hasattr(posture, "value") else str(posture)
    assert "COMPROMISED" in str(posture_str)

    stats = network_state_engine.getConnectionStats("WEB-01")
    assert stats.active >= 1
    print(f"    [PASS] Digital Twin confirmed degraded to COMPROMISED with active socket connection state.")

    print("\n" + "=" * 80)
    print("       ALL DAY 83 MULTI-SOURCE PROCESSOR TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_day83_suite()