import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.security.pipeline.events.pipeline_models import PipelineStateEnum
from services.digital_twin.security.pipeline.pipeline_orchestrator import security_event_pipeline

def provision_environment():
    device_registry.clear()
    security_state_engine.clear()
    security_event_pipeline.clear()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    db  = NetworkDeviceModel(id="DB-01",     hostname="DB-01",     type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(db)

    for dev_id in ["CLIENT-01", "WEB-01", "DB-01"]:
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

def run_day85_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 85: SECURITY EVENT PIPELINE ARCHITECTURE AUDIT")
    print("=" * 80 + "\n")

    provision_environment()

    # 1. Auditing Full 8-State Pipeline Execution on Suricata Critical Alert
    print("[1/5] Auditing Full Lifecycle on Suricata Critical Threat Alert...")
    suri_payload = {
        "timestamp": "2026-09-11T09:00:00Z",
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "src_port": 50123,
        "dest_ip": "192.168.1.20",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": "ET EXPLOIT Log4j RCE Attempt",
            "severity": 1
        }
    }

    ctx1 = security_event_pipeline.process(suri_payload)
    print(f"    Final State   : {ctx1.currentState.value}")
    print(f"    State Sequence: {[s.value for s in ctx1.history]}")

    expected_seq = [
        PipelineStateEnum.RECEIVED,
        PipelineStateEnum.PARSED,
        PipelineStateEnum.NORMALIZED,
        PipelineStateEnum.FEATURES_EXTRACTED,
        PipelineStateEnum.DETECTED,
        PipelineStateEnum.RISK_ASSESSED,
        PipelineStateEnum.ALERT_CREATED,
        PipelineStateEnum.STORED
    ]
    assert ctx1.history == expected_seq
    assert ctx1.createdAlert is not None
    assert ctx1.createdAlert.targetDevice == "WEB-01"
    assert ctx1.createdAlert.severity in ("CRITICAL", "HIGH")
    assert ctx1.createdAlert.twinPostureDegraded is True
    print("    [PASS] Full 8-stage sequence validated; ActionableSecurityAlert stored.")

    # 2. Verify Digital Twin Posture Degradation
    print("\n[2/5] Auditing Digital Twin State Integration...")
    posture = security_state_engine.getSecurityStatus("WEB-01")
    posture_str = posture.value if hasattr(posture, "value") else str(posture)
    assert "COMPROMISED" in str(posture_str)
    print(f"    [PASS] Target WEB-01 confirmed degraded to: {posture_str}.")

    # 3. Benign Flow Processing (Zeek Telemetry)
    print("\n[3/5] Auditing Benign Zeek Protocol Log Flow (Zero Alert False Positives)...")
    zeek_payload = {
        "timestamp": "2026-09-11T09:00:05Z",
        "source": "ZEEK",
        "eventType": "FLOW",
        "sourceIP": "192.168.1.10",
        "destinationIP": "192.168.1.20",
        "sourcePort": 50124,
        "destinationPort": 80,
        "protocol": "TCP",
        "bytes": 1400,
        "packets": 10
    }

    ctx2 = security_event_pipeline.process(zeek_payload)
    assert ctx2.currentState == PipelineStateEnum.STORED
    assert ctx2.detectionResult.isAnomalyOrThreat is False
    assert ctx2.createdAlert is None
    print("    [PASS] Benign Zeek flow processed cleanly through STORED with no false alert.")

    # 4. Critical Asset Multiplier Check
    print("\n[4/5] Auditing Asset Criticality Weighting on Database Tier...")
    db_threat = {
        "timestamp": "2026-09-11T09:00:10Z",
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "src_port": 50125,
        "dest_ip": "192.168.1.100",  # DB-01
        "dest_port": 5432,
        "proto": "TCP",
        "alert": {
            "signature": "ET EXPLOIT PostgreSQL Injection",
            "severity": 2
        }
    }
    ctx3 = security_event_pipeline.process(db_threat)
    assert ctx3.createdAlert.targetDevice == "DB-01"
    assert ctx3.riskAssessment.assetCriticalityMultiplier == 1.5
    assert ctx3.riskAssessment.riskScore >= 75.0
    print(f"    [PASS] Target DB-01 applied 1.5x multiplier -> Elevated Risk Score: {ctx3.riskAssessment.riskScore} (CRITICAL).")

    # 5. Fault Observability & Pipeline Failure State
    print("\n[5/5] Auditing Failure Handling & Pipeline State Observability...")
    corrupted_input = "NOT_A_VALID_JSON_STRING"
    ctx_fail = security_event_pipeline.process(corrupted_input)

    assert ctx_fail.currentState == PipelineStateEnum.FAILED
    assert ctx_fail.failedAtStage == "INGESTION"
    assert "JSON parse error" in ctx_fail.failureReason
    print(f"    [PASS] Gracefully halted at FAILED in stage '{ctx_fail.failedAtStage}': {ctx_fail.failureReason}.")

    print("\n" + "=" * 80)
    print("       ALL DAY 85 SECURITY EVENT PIPELINE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day85_suite()