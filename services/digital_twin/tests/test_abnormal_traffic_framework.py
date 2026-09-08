import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.abnormal_traffic import (
    AnomalyTypeEnum, AnomalySeverityEnum, AnomalyProfile, AbnormalEventModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.simulation.generators.abnormal_traffic_engine import abnormal_traffic_engine

def run_abnormal_framework_suite():
    print("=" * 80)
    print("       WEEK 9 - DAY 58: ABNORMAL TRAFFIC FRAMEWORK AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    abnormal_traffic_engine.clear()

    # 1. Provision Canonical Hosts
    print("[1/6] Registering Client, Web Server, and DB in Registry...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(db)
    print("    [PASS] Registered client-01, web-01, and db-01.")

    # 2. Test TRAFFIC_SPIKE
    print("\n[2/6] Testing TRAFFIC_SPIKE (Intensity = 5.0)...")
    spike_prof = AnomalyProfile(
        name="Volumetric-HTTP-Spike",
        anomalyType=AnomalyTypeEnum.TRAFFIC_SPIKE,
        severity=AnomalySeverityEnum.MEDIUM,
        affectedDevice="client-01",
        targetDevice="web-01",
        intensity=5.0,
        targetPort=443
    )
    ev_spike, pkts_spike = abnormal_traffic_engine.injectAnomaly(spike_prof, simulation_id="sim-abnormal-01")
    print(f"    Spike Event: {ev_spike.anomalyType.value} | Severity: {ev_spike.severity.value} | Pkts: {len(pkts_spike)}")
    assert ev_spike.anomalyType == AnomalyTypeEnum.TRAFFIC_SPIKE
    assert ev_spike.severity == AnomalySeverityEnum.MEDIUM
    assert len(pkts_spike) == 50  # 10 base * 5.0 intensity
    assert all(p.destinationPort == 443 for p in pkts_spike)
    print("    [PASS] TRAFFIC_SPIKE produced measurable physical packet surge.")

    # 3. Test CONNECTION_ANOMALY
    print("\n[3/6] Testing CONNECTION_ANOMALY (Rapid TCP Handshake Burst)...")
    conn_prof = AnomalyProfile(
        name="SYN-Connection-Burst",
        anomalyType=AnomalyTypeEnum.CONNECTION_ANOMALY,
        severity=AnomalySeverityEnum.HIGH,
        affectedDevice="client-01",
        targetDevice="web-01",
        intensity=4.0,
        targetPort=80
    )
    ev_conn, pkts_conn = abnormal_traffic_engine.injectAnomaly(conn_prof, simulation_id="sim-abnormal-01")
    print(f"    Connection Burst Event: {ev_conn.anomalyType.value} | Pkts: {len(pkts_conn)}")
    assert ev_conn.anomalyType == AnomalyTypeEnum.CONNECTION_ANOMALY
    assert len(pkts_conn) == 20  # 5 base * 4.0 intensity
    assert all(p.details.get("flag") == "SYN" for p in pkts_conn)
    print("    [PASS] CONNECTION_ANOMALY generated rapid TCP SYN burst.")

    # 4. Test PORT_ANOMALY
    print("\n[4/6] Testing PORT_ANOMALY (Targeting Non-Listening High Ports)...")
    port_prof = AnomalyProfile(
        name="Port-Sweep-Deviation",
        anomalyType=AnomalyTypeEnum.PORT_ANOMALY,
        severity=AnomalySeverityEnum.MEDIUM,
        affectedDevice="client-01",
        targetDevice="db-01",
        intensity=3.0
    )
    ev_port, pkts_port = abnormal_traffic_engine.injectAnomaly(port_prof, simulation_id="sim-abnormal-01")
    print(f"    Port Sweep Event: {ev_port.anomalyType.value} | Ports Probed: {len(pkts_port)}")
    assert ev_port.anomalyType == AnomalyTypeEnum.PORT_ANOMALY
    assert len(pkts_port) == 24  # 8 base * 3.0 intensity
    unique_ports = {p.destinationPort for p in pkts_port}
    assert len(unique_ports) > 10
    print(f"    [PASS] PORT_ANOMALY generated sweep across {len(unique_ports)} distinct ports.")

    # 5. Test PROTOCOL_ANOMALY & REPEATED_CONNECTION
    print("\n[5/6] Testing PROTOCOL_ANOMALY & REPEATED_CONNECTION...")
    # Protocol Anomaly
    proto_prof = AnomalyProfile(
        name="UDP-Storm-Ratio-Skew",
        anomalyType=AnomalyTypeEnum.PROTOCOL_ANOMALY,
        severity=AnomalySeverityEnum.HIGH,
        affectedDevice="client-01",
        targetDevice="web-01",
        intensity=2.0
    )
    ev_proto, pkts_proto = abnormal_traffic_engine.injectAnomaly(proto_prof, simulation_id="sim-abnormal-01")
    assert ev_proto.anomalyType == AnomalyTypeEnum.PROTOCOL_ANOMALY
    assert all(p.protocol.value == "UDP" for p in pkts_proto)
    print(f"    [PASS] PROTOCOL_ANOMALY generated {len(pkts_proto)} unexpected UDP packets against web server.")

    # Repeated Connection
    rep_prof = AnomalyProfile(
        name="Admin-SSH-Flapping",
        anomalyType=AnomalyTypeEnum.REPEATED_CONNECTION,
        severity=AnomalySeverityEnum.LOW,
        affectedDevice="client-01",
        targetDevice="web-01",
        intensity=2.0,
        targetPort=22
    )
    ev_rep, pkts_rep = abnormal_traffic_engine.injectAnomaly(rep_prof, simulation_id="sim-abnormal-01")
    assert ev_rep.anomalyType == AnomalyTypeEnum.REPEATED_CONNECTION
    assert len(pkts_rep) == 24  # 12 loops * 2 frames (SYN + RST)
    print(f"    [PASS] REPEATED_CONNECTION generated {len(pkts_rep)} flapping SYN/RST frames.")

    # 6. Boundary Invariant & Rejection Tests
    print("\n[6/6] Executing Invariant & Rejection Tests...")

    # Unknown device rejection
    try:
        bad_prof = AnomalyProfile(affectedDevice="client-01", targetDevice="ghost-server")
        abnormal_traffic_engine.injectAnomaly(bad_prof)
        assert False
    except DeviceNotFoundError:
        print("    [PASS] Rejected anomaly targeting unprovisioned device.")

    # Invalid intensity (< 1.1)
    try:
        AnomalyProfile(affectedDevice="client-01", targetDevice="web-01", intensity=0.5)
        assert False
    except ValidationError:
        print("    [PASS] Rejected invalid sub-baseline intensity (< 1.1).")

    # In-memory history check
    all_events = abnormal_traffic_engine.getAbnormalEvents()
    assert len(all_events) == 5
    print(f"    [PASS] Verified {len(all_events)} abnormal audit events in memory.")

    print("\n" + "=" * 80)
    print("       ALL DAY 58 ABNORMAL TRAFFIC FRAMEWORK TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_abnormal_framework_suite()