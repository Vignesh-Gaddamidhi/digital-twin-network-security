import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.security_state_engine import security_state_engine

from services.digital_twin.security.pipeline.features.feature_definitions import FeatureWindowEnum
from services.digital_twin.security.pipeline.detection.detection_models import DetectionTypeEnum
from services.digital_twin.security.pipeline.alerts.alert_models import AlertStatusEnum, alert_store
from services.digital_twin.security.pipeline.complete_pipeline import complete_security_pipeline

def setup_test_topology():
    device_registry.clear()
    security_state_engine.clear()
    complete_security_pipeline.clear()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    srv = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    db  = NetworkDeviceModel(id="DB-01",     hostname="DB-01",     type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(srv)
    device_registry.createDevice(db)

    for dev_id in ["CLIENT-01", "WEB-01", "SERVER-01", "DB-01"]:
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

def run_day91_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 91: COMPLETE SECURITY EVENT PIPELINE MASTER AUDIT")
    print("=" * 80 + "\n")

    setup_test_topology()
    base_t = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Benign Traffic Chain (Zero False Alerts across HTTP, HTTPS, DNS, SSH)
    print("[1/9] Auditing Benign Traffic End-to-End Chain (Zero False Alerts)...")
    benign_samples = [
        {"timestamp": base_t.isoformat(), "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "src_port": 50001, "dest_port": 80, "proto": "tcp", "bytes": 800},
        {"timestamp": (base_t + timedelta(seconds=1)).isoformat(), "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "src_port": 50002, "dest_port": 443, "proto": "tcp", "bytes": 1200},
        {"timestamp": (base_t + timedelta(seconds=2)).isoformat(), "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "src_port": 50003, "dest_port": 53, "proto": "udp", "bytes": 128},
        {"timestamp": (base_t + timedelta(seconds=3)).isoformat(), "src_ip": "192.168.1.10", "dest_ip": "192.168.1.22", "src_port": 50004, "dest_port": 22, "proto": "tcp", "bytes": 500}
    ]

    for s in benign_samples:
        r = complete_security_pipeline.process(s, source_type="suricata")
        assert r.status == "SUCCESS"
        assert r.alert is None

    assert len(alert_store.list_alerts()) == 0
    print("    [PASS] Benign flows processed through complete pipeline with zero false alerts.")

    # 2. Phase 8 Port Scan Scenario Integration (SCN-PORTSCAN-001 -> PORT_ANOMALY -> Alert)
    print("\n[2/9] Auditing SCN-PORTSCAN-001 Integration (Sweep -> PORT_ANOMALY -> Alert)...")
    sweep_ports = [21, 22, 23, 25, 80, 443, 8080]
    scan_results = []
    for idx, p in enumerate(sweep_ports):
        sweep_payload = {
            "timestamp": (base_t + timedelta(seconds=4.0 + idx * 0.1)).isoformat(),
            "src_ip": "192.168.1.10",
            "dest_ip": "192.168.1.20",
            "src_port": 49152,
            "dest_port": p,
            "proto": "tcp",
            "bytes": 60,
            "packets": 1
        }
        res_scan = complete_security_pipeline.process(sweep_payload, source_type="suricata", window=FeatureWindowEnum.WINDOW_5S)
        scan_results.append(res_scan)

    final_scan = scan_results[-1]
    assert final_scan.status == "ALERT_GENERATED"
    assert final_scan.detection.detectionType == DetectionTypeEnum.PORT_ANOMALY
    assert final_scan.alert is not None
    assert final_scan.alert.affectedDevice == "WEB-01"
    assert final_scan.alert.detectionType == "PORT_ANOMALY"
    assert final_scan.alert.protocol == "TCP"
    print(f"    [PASS] SCN-PORTSCAN-001 manifested PORT_ANOMALY (Unique Ports: {final_scan.featureVector.uniqueDestinationPorts}) -> Alert generated.")

    # 3. Controlled Digital Twin State Transition Verification
    print("\n[3/9] Auditing Controlled Posture Transition (Scan -> SUSPICIOUS, Not Blindly COMPROMISED)...")
    web_posture = security_state_engine.getSecurityStatus("WEB-01")
    web_val = web_posture.value if hasattr(web_posture, "value") else str(web_posture)
    print(f"    WEB-01 Posture after Port Scan: {web_val}")
    assert web_val in ("SUSPICIOUS", "UNDER_ATTACK")
    assert web_val != "COMPROMISED"
    print("    [PASS] Digital Twin graduated to SUSPICIOUS/UNDER_ATTACK without jumping directly to COMPROMISED.")

    # 4. Volumetric Traffic Spike (SCN-DOS-001 -> TRAFFIC_SPIKE -> Alert)
    print("\n[4/9] Auditing SCN-DOS-001 Integration (Volumetric Saturation Spike)...")
    spike_payload = {
        "timestamp": (base_t + timedelta(seconds=15.0)).isoformat(),
        "src_ip": "192.168.1.10",
        "dest_ip": "192.168.1.20",
        "src_port": 49153,
        "dest_port": 443,
        "proto": "tcp",
        "bytes": 250000,
        "packets": 300,
        "direction": "INBOUND",
        "metadata": {"direction": "INBOUND"}
    }
    res_spike = complete_security_pipeline.process(spike_payload, source_type="suricata", window=FeatureWindowEnum.WINDOW_5S)
    assert res_spike.status == "ALERT_GENERATED"
    assert res_spike.detection.detectionType == DetectionTypeEnum.TRAFFIC_SPIKE
    assert res_spike.alert.riskLevel in ("MEDIUM", "HIGH", "CRITICAL")
    print(f"    [PASS] Volumetric burst flagged TRAFFIC_SPIKE (ByteRate: {res_spike.featureVector.byteRate} B/s).")

    # 5. C2 Beaconing Pattern Integration (SCN-BEACON-001 -> Zero-Variance Timing)
    print("\n[5/9] Auditing SCN-BEACON-001 Integration (Low-Jitter Heartbeats)...")
    beacon_base = datetime(2026, 9, 11, 11, 0, 0, tzinfo=timezone.utc)
    beacon_results = []
    for i in range(8):
        ts_str = (beacon_base + timedelta(seconds=float(i) * 1.0)).isoformat()
        b_payload = {
            "ts": ts_str,
            "timestamp": ts_str,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "192.168.1.22",
            "id.orig_p": 50123,
            "id.resp_p": 22,
            "proto": "tcp",
            "orig_bytes": 100,
            "resp_bytes": 100
        }
        res_b = complete_security_pipeline.process(b_payload, source_type="zeek", window=FeatureWindowEnum.WINDOW_30S)
        beacon_results.append(res_b)

    final_beacon = beacon_results[-1]
    assert final_beacon.detection.detectionType == DetectionTypeEnum.BEACONING_PATTERN
    assert final_beacon.alert is not None
    assert final_beacon.alert.riskLevel in ("MEDIUM", "HIGH", "CRITICAL")
    print(f"    [PASS] Periodic heartbeats produced BEACONING_PATTERN alert (Variance: {final_beacon.featureVector.intervalVariance}s^2).")

    # 6. Critical Exfiltration & Target Compromise (SCN-EXFIL-001 -> DB-01 COMPROMISED)
    print("\n[6/9] Auditing SCN-EXFIL-001 Integration (Database Exfiltration -> COMPROMISED)...")
    exfil_payload = {
        "timestamp": (base_t + timedelta(seconds=60.0)).isoformat(),
        "sourceDevice": "CLIENT-01",
        "destinationDevice": "DB-01",
        "destinationPort": 5432,
        "protocol": "TCP",
        "bytes": 450000,
        "packets": 350,
        "direction": "OUTBOUND",
        "metadata": {"direction": "OUTBOUND"}
    }
    res_exfil = complete_security_pipeline.process(exfil_payload, source_type="simulation", window=FeatureWindowEnum.WINDOW_5S)
    assert res_exfil.status == "ALERT_GENERATED"
    assert res_exfil.alert.riskLevel == "CRITICAL"
    assert res_exfil.twinPostureUpdated is True
    assert res_exfil.newTwinPosture == "COMPROMISED"

    db_posture = security_state_engine.getSecurityStatus("DB-01")
    assert "COMPROMISED" in (db_posture.value if hasattr(db_posture, "value") else str(db_posture))
    print(f"    [PASS] Critical exfiltration drove target DB-01 to COMPROMISED (Score: {res_exfil.alert.riskScore}).")

    # 7. Alert Deduplication & Lifecycle State Management
    print("\n[7/9] Auditing Alert Deduplication & Status Lifecycle Management...")
    alert_id = res_exfil.alert.alertId
    res_dup = complete_security_pipeline.process(exfil_payload, source_type="simulation", window=FeatureWindowEnum.WINDOW_5S)
    assert res_dup.isDuplicateAlert is True
    print("    [PASS] Re-transmitting identical threat within window was deduplicated.")

    # Status transitions: NEW -> INVESTIGATING -> RESOLVED
    assert alert_store.update_status(alert_id, AlertStatusEnum.INVESTIGATING) is True
    assert alert_store.get_alert(alert_id).status == AlertStatusEnum.INVESTIGATING
    assert alert_store.update_status(alert_id, AlertStatusEnum.RESOLVED) is True
    assert alert_store.get_alert(alert_id).status == AlertStatusEnum.RESOLVED
    print(f"    [PASS] Alert lifecycle updated: NEW -> INVESTIGATING -> RESOLVED for {alert_id}.")

    # 8. Failure & Fault Resilience Tests
    print("\n[8/9] Auditing Failure Handling (Malformed Inputs, Missing Headers, Bad Ports)...")
    f1 = complete_security_pipeline.process({"src_ip": "192.168.1.10"})
    assert f1.status == "REJECTED"
    assert f1.errorCode == "NORMALIZATION_ERROR"

    f2 = complete_security_pipeline.process({"timestamp": "2026-09-11T10:00:00Z", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "dest_port": 999999})
    assert f2.status == "REJECTED"

    f3 = complete_security_pipeline.process("CORRUPTED_RAW_STRING")
    assert f3.status == "REJECTED"
    print("    [PASS] Fault resilience verified: All malformed inputs safely quarantined without system crashes.")

    # 9. Pipeline Observability & Stage Duration Verification
    print("\n[9/9] Auditing Pipeline Observability & Stage Latency Tracking...")
    assert final_scan.durations.normalizationMs > 0
    assert final_scan.durations.featureExtractionMs > 0
    assert final_scan.durations.detectionMs > 0
    assert final_scan.durations.riskAssessmentMs > 0
    assert final_scan.durations.totalMs > 0
    print(f"    Stage Durations for Run {final_scan.pipelineRunId}:")
    print(f"      - Normalization       : {final_scan.durations.normalizationMs:.3f} ms")
    print(f"      - Feature Extraction  : {final_scan.durations.featureExtractionMs:.3f} ms")
    print(f"      - Detection           : {final_scan.durations.detectionMs:.3f} ms")
    print(f"      - Risk Assessment     : {final_scan.durations.riskAssessmentMs:.3f} ms")
    print(f"      - Alert Generation    : {final_scan.durations.alertGenerationMs:.3f} ms")
    print(f"      - Total Execution     : {final_scan.durations.totalMs:.3f} ms")
    print("    [PASS] Comprehensive stage metrics recorded.")

    print("\n" + "=" * 80)
    print("       ALL 9 MASTER INTEGRATION TEST AUDITS PASSED CLEANLY")
    print("       PHASE 10: SECURITY EVENT PIPELINE OFFICIALLY GRADUATED")
    print("=" * 80)

if __name__ == "__main__":
    run_day91_suite()