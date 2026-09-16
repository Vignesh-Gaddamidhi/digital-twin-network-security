import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select, delete
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import (
    Simulation, SimulationRun, SimulationEvent,
    Vulnerability, AuditLog, Dataset, MLExperiment, MLModel,
    SimulationStatusEnum, VulnerabilityStatusEnum, ExecutionModeEnum, AuditActionEnum
)

class GovernanceSimulationRepository:
    """SQLAlchemy 2.0 DAL for Simulations, CVE Vulnerabilities, Audit Logs, and ML Governance."""

    # ==================== SIMULATIONS ====================

    @staticmethod
    async def create_simulation(
        simulation_id: str,
        name: str,
        scenario: str,
        description: Optional[str] = None,
        default_configuration: Optional[Dict[str, Any]] = None
    ) -> Simulation:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Simulation).where(Simulation.simulation_id == simulation_id))
            sim = res.scalar_one_or_none()
            if not sim:
                sim = Simulation(
                    simulation_id=simulation_id,
                    name=name,
                    scenario=scenario,
                    description=description,
                    default_configuration=default_configuration or {}
                )
                sess.add(sim)
            else:
                sim.name = name
                sim.scenario = scenario
                sim.description = description
                sim.default_configuration = default_configuration or {}
            await sess.flush()
            return sim

    @staticmethod
    async def record_simulation_run(
        run_id: str,
        simulation_id: str,
        scenario: str,
        status: str = "COMPLETED",
        seed: int = 42,
        speed: float = 1.0,
        tick_interval: float = 1.0,
        duration: float = 60.0,
        prediction_horizon: int = 30,
        event_count: int = 0,
        result: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> SimulationRun:
        st_enum = SimulationStatusEnum(status.upper()) if isinstance(status, str) else status
        now = start_time or datetime.now(timezone.utc)

        async with db_manager.session() as sess:
            res = await sess.execute(select(SimulationRun).where(SimulationRun.run_id == run_id))
            run = res.scalar_one_or_none()
            if not run:
                run = SimulationRun(
                    run_id=run_id,
                    simulation_id=simulation_id,
                    scenario=scenario,
                    start_time=now,
                    end_time=end_time,
                    status=st_enum,
                    seed=seed,
                    speed=speed,
                    tick_interval=tick_interval,
                    duration=duration,
                    prediction_horizon=prediction_horizon,
                    event_count=event_count,
                    result=result or {}
                )
                sess.add(run)
            else:
                run.status = st_enum
                run.end_time = end_time
                run.event_count = event_count
                run.result = result or {}
            await sess.flush()
            return run

    @staticmethod
    async def record_simulation_event(
        event_id: str,
        run_id: str,
        device_id: str,
        event_type: str,
        source: str,
        destination: str,
        protocol: str = "TCP",
        payload_metadata: Optional[Dict[str, Any]] = None,
        result: str = "PROCESSED",
        timestamp: Optional[datetime] = None
    ) -> SimulationEvent:
        ts = timestamp or datetime.now(timezone.utc)
        async with db_manager.session() as sess:
            res = await sess.execute(select(SimulationEvent).where(SimulationEvent.event_id == event_id))
            ev = res.scalar_one_or_none()
            if not ev:
                ev = SimulationEvent(
                    event_id=event_id,
                    run_id=run_id,
                    timestamp=ts,
                    device_id=device_id,
                    event_type=event_type,
                    protocol=protocol,
                    source=source,
                    destination=destination,
                    payload_metadata=payload_metadata or {},
                    result=result
                )
                sess.add(ev)
            else:
                ev.run_id = run_id
                ev.event_type = event_type
                ev.result = result
                ev.payload_metadata = payload_metadata or {}
            await sess.flush()
            return ev

    # ==================== VULNERABILITIES ====================

    @staticmethod
    async def record_vulnerability(
        vulnerability_id: str,
        device_id: str,
        identifier: str,
        title: str,
        severity: str,
        cvss_score: float,
        description: Optional[str] = None,
        affected_service: Optional[str] = None,
        affected_port: Optional[int] = None,
        status: str = "OPEN",
        evidence: Optional[str] = None
    ) -> Vulnerability:
        st_enum = VulnerabilityStatusEnum(status.upper()) if isinstance(status, str) else status
        async with db_manager.session() as sess:
            res = await sess.execute(select(Vulnerability).where(Vulnerability.vulnerability_id == vulnerability_id))
            vuln = res.scalar_one_or_none()
            if not vuln:
                vuln = Vulnerability(
                    vulnerability_id=vulnerability_id,
                    device_id=device_id,
                    identifier=identifier,
                    title=title,
                    description=description,
                    severity=severity.upper(),
                    cvss_score=float(cvss_score),
                    affected_service=affected_service,
                    affected_port=affected_port,
                    status=st_enum,
                    evidence=evidence
                )
                sess.add(vuln)
            else:
                vuln.status = st_enum
                vuln.cvss_score = float(cvss_score)
                vuln.evidence = evidence
            await sess.flush()
            return vuln

    # ==================== AUDIT LOGS & SAFETY BOUNDARY ====================

    @staticmethod
    async def record_audit_entry(
        audit_id: str,
        operator_id: str,
        action: str,
        object_type: str,
        object_id: str,
        new_state: str,
        mode: str = "SIMULATION",
        previous_state: Optional[str] = None,
        reason: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> AuditLog:
        """
        Records tamper-evident audit ledger entries.
        Enforces Week 25 Safety Boundary: Real network modifications are blocked.
        """
        mode_enum = ExecutionModeEnum(mode.upper()) if isinstance(mode, str) else mode
        action_enum = AuditActionEnum(action.upper()) if isinstance(action, str) else action
        ts = timestamp or datetime.now(timezone.utc)

        if mode_enum == ExecutionModeEnum.REAL:
            result_status = "REJECTED_SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED"
        else:
            result_status = "SUCCESS"

        async with db_manager.session() as sess:
            log = AuditLog(
                audit_id=audit_id,
                timestamp=ts,
                operator_id=operator_id,
                action=action_enum,
                object_type=object_type,
                object_id=object_id,
                previous_state=previous_state,
                new_state=new_state,
                mode=mode_enum,
                result=result_status,
                reason=reason
            )
            sess.add(log)
            await sess.flush()

            if mode_enum == ExecutionModeEnum.REAL:
                raise PermissionError("SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED: Only SIMULATION mode is permitted.")

            return log

    # ==================== ML GOVERNANCE ====================

    @staticmethod
    async def record_dataset(
        dataset_id: str,
        name: str,
        version: str,
        source: str,
        row_count: int,
        feature_count: int,
        label_definition: Dict[str, Any],
        description: Optional[str] = None,
        feature_version: str = "v1.0"
    ) -> Dataset:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Dataset).where(Dataset.dataset_id == dataset_id))
            ds = res.scalar_one_or_none()
            if not ds:
                ds = Dataset(
                    dataset_id=dataset_id,
                    name=name,
                    version=version,
                    description=description,
                    source=source,
                    feature_version=feature_version,
                    row_count=row_count,
                    feature_count=feature_count,
                    label_definition=label_definition
                )
                sess.add(ds)
            else:
                ds.row_count = row_count
                ds.feature_count = feature_count
            await sess.flush()
            return ds

    @staticmethod
    async def record_ml_experiment(
        experiment_id: str,
        name: str,
        model_name: str,
        model_version: str,
        parameters: Dict[str, Any],
        accuracy: float,
        precision: float,
        recall: float,
        f1_score: float,
        roc_auc: float,
        training_time: float,
        inference_time: float,
        confusion_matrix: Dict[str, Any],
        dataset_id: Optional[str] = None,
        description: Optional[str] = None,
        feature_version: str = "v1.0"
    ) -> MLExperiment:
        async with db_manager.session() as sess:
            res = await sess.execute(select(MLExperiment).where(MLExperiment.experiment_id == experiment_id))
            exp = res.scalar_one_or_none()
            if not exp:
                exp = MLExperiment(
                    experiment_id=experiment_id,
                    name=name,
                    description=description,
                    model_name=model_name,
                    model_version=model_version,
                    dataset_id=dataset_id,
                    feature_version=feature_version,
                    parameters=parameters,
                    accuracy=float(accuracy),
                    precision=float(precision),
                    recall=float(recall),
                    f1_score=float(f1_score),
                    roc_auc=float(roc_auc),
                    training_time=float(training_time),
                    inference_time=float(inference_time),
                    confusion_matrix=confusion_matrix
                )
                sess.add(exp)
            await sess.flush()
            return exp

    @staticmethod
    async def record_ml_model(
        model_id: str,
        name: str,
        version: str,
        model_type: str,
        metrics: Dict[str, Any],
        model_size: float,
        inference_latency: float,
        artifact_reference: str,
        dataset_id: Optional[str] = None,
        feature_version: str = "v1.0",
        status: str = "PRODUCTION"
    ) -> MLModel:
        async with db_manager.session() as sess:
            res = await sess.execute(select(MLModel).where(MLModel.model_id == model_id))
            m = res.scalar_one_or_none()
            if not m:
                m = MLModel(
                    model_id=model_id,
                    name=name,
                    version=version,
                    model_type=model_type,
                    dataset_id=dataset_id,
                    feature_version=feature_version,
                    metrics=metrics,
                    model_size=float(model_size),
                    inference_latency=float(inference_latency),
                    status=status,
                    artifact_reference=artifact_reference
                )
                sess.add(m)
            else:
                m.status = status
                m.metrics = metrics
            await sess.flush()
            return m

gov_sim_repo = GovernanceSimulationRepository()