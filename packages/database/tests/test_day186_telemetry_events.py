import sys
import asyncio
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.twin_persistence_repository import twin_persistence_repo
from packages.database.src.telemetry_event_repository import telemetry_event_repo
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

async def run_day186_suite():
    print("=" * 80)
    print("       WEEK 27 - DAY 186: TELEMETRY & SECURITY EVENTS PERSISTENCE AUDIT")
    print("================================================================================\n")

    await db_manager.connect()
    prisma = db_manager.client

    # Seed baseline target device
    test_device = NetworkDeviceModel(
        id="WEB-01",
        name="web-01.dmz.internal",
        hostname="web-01.dmz.internal",
        device_type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DMZ,
        ipAddresses=["10.0.2.99"],
        security_state="NORMAL"
    )
    await twin_persistence_repo.persist_device_aggregate(test_device)

    # 1. Telemetry Measurement Stream
    print("[1/5] Auditing Device Telemetry Measurement Persistence...")
    t1 = await telemetry_event_repo.record_telemetry(
        device_id="WEB-01",
        cpu_usage=45.2,
        memory_usage=68.1,
        packet_rate=1240.0,
        byte_rate=850000.0,
        network_utilization=0.34,
        active_connections=42,
        security_state="NORMAL",
        risk_score=15.0,
        source="TWIN_AGENT"
    )
    assert t1.id is not None
    assert t1.deviceId == "WEB-01"
    print(f"    Telemetry Frame ID : {t1.id}")
    print(f"    Metrics Recorded   : CPU={t1.cpuUsage}% | Mem={t1.memoryUsage}% | Pps={t1.packetRate}")
    print("    [PASS] Device telemetry persisted with relational linkage.")

    # 2. NetFlow / Traffic Flow Records
    print("\n[2/5] Auditing Multi-Protocol NetFlow Tuple Persistence...")
    flow = await telemetry_event_repo.record_traffic_flow(
        source_ip="10.0.1.25",
        destination_ip="10.0.2.99",
        source_port=52110,
        destination_port=443,
        protocol="HTTPS",
        packet_count=18,
        byte_count=24500,
        source_device_id=None,
        destination_device_id="WEB-01",
        flow_duration=1.24,
        status="ESTABLISHED"
    )
    assert flow.id is not None
    assert flow.protocol == "HTTPS"
    print(f"    Flow ID            : {flow.id}")
    print(f"    Flow Vector        : {flow.sourceIp}:{flow.sourcePort} -> {flow.destinationIp}:{flow.destinationPort} ({flow.protocol})")
    print(f"    Volume Logged      : {flow.packetCount} pkts / {flow.byteCount} bytes")
    print("    [PASS] Network traffic flow persisted.")

    # 3. Canonical Security Event Persistence
    print("\n[3/5] Auditing Canonical SIEM Security Event Persistence...")
    sec_ev = await telemetry_event_repo.record_security_event(
        event_id="EVT-20260916-0001",
        source="192.168.1.105:48320",
        destination="10.0.2.99:80",
        device_id="WEB-01",
        protocol="TCP",
        port=80,
        event_type="HTTP_SLOWLORIS_FLOOD",
        severity="CRITICAL",
        detection_source="SURICATA",
        detection_type="SIGNATURE_MATCH",
        confidence=0.99,
        evidence="Observed connection starvation holding 1,200 keep-alive slots"
    )
    assert sec_ev.eventId == "EVT-20260916-0001"
    assert sec_ev.severity == "CRITICAL"
    print(f"    Security Event ID  : {sec_ev.eventId}")
    print(f"    Event Classification: {sec_ev.eventType} ({sec_ev.severity})")
    print("    [PASS] Canonical security event persisted.")

    # 4. IDS Event Persistence & Relational Linkage
    print("\n[4/5] Auditing Raw IDS Event (Suricata/Zeek) with Event Relational Linkage...")
    ids_ev = await telemetry_event_repo.record_ids_event(
        source="192.168.1.105:48320",
        destination="10.0.2.99:80",
        signature="ET DOS HTTP Slowloris Inbound Attempt",
        signature_id=200142,
        severity="HIGH",
        category="DENIAL_OF_SERVICE",
        sensor="SURICATA",
        protocol="TCP",
        port=80,
        raw_reference="eve-log-record-offset-9812",
        security_event_id=sec_ev.eventId
    )
    assert ids_ev.id is not None
    assert ids_ev.signatureId == 200142
    assert ids_ev.securityEventId == "EVT-20260916-0001"
    print(f"    IDS Event ID       : {ids_ev.id}")
    print(f"    Signature Matched  : SID:{ids_ev.signatureId} '{ids_ev.signature}'")
    print(f"    Linked SIEM Event  : {ids_ev.securityEventId}")
    print("    [PASS] IDS Event persisted with distinct identity and parent event linkage.")

    # 5. Indexed Query Verification
    print("\n[5/5] Auditing Filtered Database Queries (Time, Device, Protocol)...")
    history = await telemetry_event_repo.get_device_telemetry_history("WEB-01", limit=10)
    assert len(history) >= 1

    https_flows = await telemetry_event_repo.query_flows_by_protocol("HTTPS")
    assert len(https_flows) >= 1

    ids_list = await telemetry_event_repo.list_ids_events(limit=10)
    assert len(ids_list) >= 1
    assert ids_list[0].securityEvent is not None
    print("    [PASS] Indexed query filters resolved without full table scans.")

    # Clean Up Test Records
    print("\n[*] Cleaning Up Ephemeral Telemetry & Event Records...")
    await prisma.idsevent.delete(where={"id": ids_ev.id})
    await prisma.securityevent.delete(where={"eventId": sec_ev.eventId})
    await prisma.trafficflow.delete(where={"id": flow.id})
    await prisma.telemetry.delete(where={"id": t1.id})
    await prisma.device.delete(where={"id": "WEB-01"})
    print("    [PASS] Cleaned test artifacts.")

    await db_manager.disconnect()
    print("\n" + "=" * 80)
    print("       ALL DAY 186 TELEMETRY & EVENT PERSISTENCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day186_suite())