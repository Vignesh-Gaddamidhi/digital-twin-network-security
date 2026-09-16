import sys
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import delete

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.models import (
    Device, Simulation, SimulationRun, SimulationEvent,
    Vulnerability, AuditLog, Dataset, MLExperiment, MLModel,
    ExecutionModeEnum, AuditActionEnum
)
from packages.database.src.twin_persistence_repository import twin_persistence_repo
from packages.database.src.governance_simulation_repository import gov_sim_repo
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

async def run_day188_suite():
    print("=" * 80)
    print("       WEEK 27 - DAY 188: SIMULATION, AUDIT & ML GOVERNANCE AUDIT")
    print("================================================================================\n")

    # 0. Pre-clean any leftover artifacts from interrupted previous runs
    async with db_manager.session() as sess:
        await sess.execute(delete(SimulationEvent).where(SimulationEvent.event_id == "EVT-SIM-001"))
        await sess.execute(delete(SimulationRun).where(SimulationRun.run_id == "RUN-20260916-001"))
        await sess.execute(delete(Simulation).where(Simulation.simulation_id == "SIM-LATERAL-MOVE"))
        await sess.execute(delete(Vulnerability).where(Vulnerability.vulnerability_id == "VULN-2026-001"))
        await sess.execute(delete(AuditLog).where(AuditLog.audit_id.in_(["AUD-SIM-001", "AUD-REAL-REJECTED"])))
        await sess.execute(delete(MLModel).where(MLModel.model_id == "MDL-XGB-PROD"))
        await sess.execute(delete(MLExperiment).where(MLExperiment.experiment_id == "EXP-XGB-001"))
        await sess.execute(delete(Dataset).where(Dataset.dataset_id == "DS-SYNTH-V1"))
        await sess.flush()

    # Seed target device
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

    # 1. Simulation Definitions & Runs
    print("[1/5] Auditing Simulation Engine & Execution Run Persistence...")
    sim = await gov_sim_repo.create_simulation(
        simulation_id="SIM-LATERAL-MOVE",
        name="Lateral Movement via Web DMZ",
        scenario="LATERAL_MOVEMENT_LIKE",
        description="Simulates adversary hop from compromised Web Proxy to internal Database tier.",
        default_configuration={"duration_sec": 45, "rate_pps": 250}
    )
    assert sim.simulation_id == "SIM-LATERAL-MOVE"

    run = await gov_sim_repo.record_simulation_run(
        run_id="RUN-20260916-001",
        simulation_id=sim.simulation_id,
        scenario=sim.scenario,
        status="COMPLETED",
        duration=45.0,
        event_count=120,
        result={"reachability": "BLOCKED", "contained": True}
    )
    assert run.run_id == "RUN-20260916-001"

    ev = await gov_sim_repo.record_simulation_event(
        event_id="EVT-SIM-001",
        run_id=run.run_id,
        device_id="WEB-01",
        event_type="RPC_PORT_DISCOVERY",
        source="10.0.1.25",
        destination="10.0.2.99",
        protocol="TCP",
        payload_metadata={"port": 135, "ttl": 64}
    )
    assert ev.event_id == "EVT-SIM-001"
    print(f"    Simulation Registered: {sim.name} ({sim.scenario})")
    print(f"    Execution Run ID     : {run.run_id} ({run.status})")
    print(f"    Generated Event ID   : {ev.event_id}")
    print("    [PASS] Simulation models persisted.")

    # 2. Vulnerability Persistence
    print("\n[2/5] Auditing CVE Vulnerability Ledger...")
    vuln = await gov_sim_repo.record_vulnerability(
        vulnerability_id="VULN-2026-001",
        device_id="WEB-01",
        identifier="CVE-2026-38408",
        title="OpenSSH Remote Code Execution via PKCS#11",
        severity="CRITICAL",
        cvss_score=9.8,
        affected_service="OpenSSH",
        affected_port=22,
        status="OPEN",
        evidence="Vulnerable sshd daemon banner observed: OpenSSH_9.2"
    )
    assert vuln.vulnerability_id == "VULN-2026-001"
    assert vuln.cvss_score == 9.8
    print(f"    CVE Registered       : {vuln.identifier} ({vuln.severity})")
    print(f"    Affected Service     : {vuln.affected_service}:{vuln.affected_port}")
    print("    [PASS] Vulnerability record persisted with device foreign key.")

    # 3. Audit Ledger & Hard Safety Boundary
    print("\n[3/5] Auditing Tamper-Evident Forensic Audit Ledger & Hard Safety Boundary...")
    # A: Safe Simulation Execution
    audit_sim = await gov_sim_repo.record_audit_entry(
        audit_id="AUD-SIM-001",
        operator_id="SOC_LEAD_ANALYST",
        action="ISOLATE_DEVICE",
        object_type="DEVICE",
        object_id="WEB-01",
        previous_state="AT_RISK",
        new_state="ISOLATED",
        mode="SIMULATION",
        reason="Elevated risk score (84.5) mandates immediate containment."
    )
    assert audit_sim.result == "SUCCESS"
    print(f"    [SIMULATION Mode] Audit ID: {audit_sim.audit_id} -> Result: {audit_sim.result}")

    # B: Real-World Execution Rejection Guardrail
    blocked_flag = False
    try:
        await gov_sim_repo.record_audit_entry(
            audit_id="AUD-REAL-REJECTED",
            operator_id="SOC_LEAD_ANALYST",
            action="ISOLATE_DEVICE",
            object_type="DEVICE",
            object_id="WEB-01",
            previous_state="NORMAL",
            new_state="ISOLATED",
            mode="REAL",
            reason="Illegal attempt to modify real-world physical switch fabric."
        )
    except PermissionError as e:
        blocked_flag = True
        print(f"    [REAL Mode Blocked] Hard safety boundary caught violation: {e}")

    assert blocked_flag is True
    print("    [PASS] Audit trail verified; REAL execution blocked by safety validator.")

    # 4. ML Governance: Datasets, Experiments & Models
    print("\n[4/5] Auditing ML Governance Layer (Dataset, Experiments, Models)...")
    ds = await gov_sim_repo.record_dataset(
        dataset_id="DS-SYNTH-V1",
        name="Synthetic Digital Twin Cyber Attacks",
        version="v1.0.0",
        source="SimulationEngine-Run001-to-050",
        row_count=100000,
        feature_count=42,
        label_definition={"0": "BENIGN", "1": "PORT_SCAN", "2": "DOS", "3": "LATERAL_MOVEMENT"}
    )
    assert ds.dataset_id == "DS-SYNTH-V1"

    exp = await gov_sim_repo.record_ml_experiment(
        experiment_id="EXP-XGB-001",
        name="XGBoost Lateral Movement Benchmark",
        model_name="XGBoost",
        model_version="v1.2.0",
        dataset_id=ds.dataset_id,
        parameters={"n_estimators": 100, "max_depth": 6, "learning_rate": 0.05},
        accuracy=0.984,
        precision=0.978,
        recall=0.981,
        f1_score=0.979,
        roc_auc=0.992,
        training_time=14.2,
        inference_time=0.003,
        confusion_matrix={"TP": 196, "FP": 4, "TN": 792, "FN": 8}
    )
    assert exp.experiment_id == "EXP-XGB-001"
    assert exp.roc_auc == 0.992

    m = await gov_sim_repo.record_ml_model(
        model_id="MDL-XGB-PROD",
        name="XGBoost_Classifier_V1",
        version="v1.2.0",
        model_type="XGBoost",
        dataset_id=ds.dataset_id,
        metrics={"f1": 0.979, "auc": 0.992},
        model_size=12.4,
        inference_latency=0.003,
        status="PRODUCTION",
        artifact_reference="s3://cyber-models/production/xgboost_v1.2.0.joblib"
    )
    assert m.model_id == "MDL-XGB-PROD"
    print(f"    Dataset Registered   : {ds.name} ({ds.row_count} records)")
    print(f"    Experiment Recorded  : {exp.name} (F1={exp.f1_score})")
    print(f"    Model Registry Entry : {m.name} -> {m.artifact_reference}")
    print("    [PASS] ML governance metadata persisted.")

    # 5. Cleanup Test Records
    print("\n[5/5] Cleaning Up Ephemeral Day 188 Test Records...")
    async with db_manager.session() as sess:
        await sess.execute(delete(MLModel).where(MLModel.model_id == m.model_id))
        await sess.execute(delete(MLExperiment).where(MLExperiment.experiment_id == exp.experiment_id))
        await sess.execute(delete(Dataset).where(Dataset.dataset_id == ds.dataset_id))
        await sess.execute(delete(AuditLog).where(AuditLog.audit_id.in_(["AUD-SIM-001", "AUD-REAL-REJECTED"])))
        await sess.execute(delete(Vulnerability).where(Vulnerability.vulnerability_id == vuln.vulnerability_id))
        await sess.execute(delete(SimulationEvent).where(SimulationEvent.event_id == ev.event_id))
        await sess.execute(delete(SimulationRun).where(SimulationRun.run_id == run.run_id))
        await sess.execute(delete(Simulation).where(Simulation.simulation_id == sim.simulation_id))
        await sess.execute(delete(Device).where(Device.id == "WEB-01"))
        await sess.flush()
    print("    [PASS] Test artifacts cleanly removed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 188 SIMULATION, AUDIT & ML GOVERNANCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day188_suite())