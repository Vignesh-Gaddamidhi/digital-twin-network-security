import uuid
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from sqlalchemy import select, update, delete, func, desc
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import (
    Device, DeviceInterface, DeviceService, DevicePort, NetworkConnection, TopologyEdge,
    Telemetry, TrafficFlow, SecurityEvent, IdsEvent,
    Alert, Incident, Prediction, TemporalPrediction, XaiExplanation, RiskAssessment, AttackPath,
    Simulation, SimulationRun, SimulationEvent, Vulnerability, AuditLog, Dataset, MLExperiment, MLModel,
    AlertStatusEnum, IncidentStatusEnum, AuditActionEnum, ExecutionModeEnum
)

class PaginatedResult:
    def __init__(self, items: List[Any], total: int, page: int, page_size: int):
        self.items = items
        self.total = total
        self.page = page
        self.page_size = page_size
        self.total_pages = (total + page_size - 1) // page_size if page_size > 0 else 1

class UnifiedRepository:
    """Master Data Access Layer for the Digital Twin Security Platform."""

    # ==================== DEVICE REPOSITORY ====================
    @staticmethod
    async def get_devices_paginated(
        page: int = 1,
        page_size: int = 50,
        zone: Optional[str] = None,
        security_state: Optional[str] = None
    ) -> PaginatedResult:
        offset = (page - 1) * page_size
        async with db_manager.session() as sess:
            query = select(Device)
            count_query = select(func.count(Device.id))

            if zone:
                query = query.where(Device.network_zone == zone.upper())
                count_query = count_query.where(Device.network_zone == zone.upper())
            if security_state:
                query = query.where(Device.security_state == security_state.upper())
                count_query = count_query.where(Device.security_state == security_state.upper())

            total_res = await sess.execute(count_query)
            total = total_res.scalar() or 0

            res = await sess.execute(
                query.options(
                    selectinload(Device.interfaces),
                    selectinload(Device.services),
                    selectinload(Device.ports)
                ).order_by(Device.id.asc()).offset(offset).limit(page_size)
            )
            return PaginatedResult(list(res.scalars().all()), total, page, page_size)

    # ==================== ALERT REPOSITORY ====================
    @staticmethod
    async def get_alerts_paginated(
        page: int = 1,
        page_size: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        device_id: Optional[str] = None
    ) -> PaginatedResult:
        offset = (page - 1) * page_size
        async with db_manager.session() as sess:
            query = select(Alert)
            count_query = select(func.count(Alert.alert_id))

            if severity:
                query = query.where(Alert.severity == severity.upper())
                count_query = count_query.where(Alert.severity == severity.upper())
            if status:
                st_enum = AlertStatusEnum(status.upper())
                query = query.where(Alert.status == st_enum)
                count_query = count_query.where(Alert.status == st_enum)
            if device_id:
                query = query.where(Alert.affected_device_id == device_id)
                count_query = count_query.where(Alert.affected_device_id == device_id)

            total_res = await sess.execute(count_query)
            total = total_res.scalar() or 0

            res = await sess.execute(
                query.options(selectinload(Alert.affected_device))
                .order_by(desc(Alert.timestamp))
                .offset(offset).limit(page_size)
            )
            return PaginatedResult(list(res.scalars().all()), total, page, page_size)

    # ==================== INCIDENT REPOSITORY ====================
    @staticmethod
    async def get_incidents_paginated(
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        severity: Optional[str] = None
    ) -> PaginatedResult:
        offset = (page - 1) * page_size
        async with db_manager.session() as sess:
            query = select(Incident)
            count_query = select(func.count(Incident.incident_id))

            if status:
                st_enum = IncidentStatusEnum(status.upper())
                query = query.where(Incident.status == st_enum)
                count_query = count_query.where(Incident.status == st_enum)
            if severity:
                query = query.where(Incident.severity == severity.upper())
                count_query = count_query.where(Incident.severity == severity.upper())

            total_res = await sess.execute(count_query)
            total = total_res.scalar() or 0

            res = await sess.execute(
                query.options(
                    selectinload(Incident.alerts),
                    selectinload(Incident.attack_paths)
                ).order_by(desc(Incident.created_at)).offset(offset).limit(page_size)
            )
            return PaginatedResult(list(res.scalars().all()), total, page, page_size)

    # ==================== AUDIT REPOSITORY ====================
    @staticmethod
    async def get_audit_logs_paginated(
        page: int = 1,
        page_size: int = 50,
        action: Optional[str] = None,
        operator_id: Optional[str] = None
    ) -> PaginatedResult:
        offset = (page - 1) * page_size
        async with db_manager.session() as sess:
            query = select(AuditLog)
            count_query = select(func.count(AuditLog.audit_id))

            if action:
                act_enum = AuditActionEnum(action.upper())
                query = query.where(AuditLog.action == act_enum)
                count_query = count_query.where(AuditLog.action == act_enum)
            if operator_id:
                query = query.where(AuditLog.operator_id == operator_id)
                count_query = count_query.where(AuditLog.operator_id == operator_id)

            total_res = await sess.execute(count_query)
            total = total_res.scalar() or 0

            res = await sess.execute(
                query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(page_size)
            )
            return PaginatedResult(list(res.scalars().all()), total, page, page_size)

    # ==================== TRANSACTION: SAFE RESPONSE SIMULATION ====================
    @staticmethod
    async def execute_simulated_response_transaction(
        device_id: str,
        action: str,
        operator_id: str,
        reason: str,
        mode: str = "SIMULATION"
    ) -> Tuple[Device, AuditLog]:
        """
        Atomic Unit of Work:
        1. Validates safety boundary (REAL mode is strictly blocked).
        2. Mutates persistent Device state.
        3. Commits tamper-evident Audit Log entry.
        """
        mode_enum = ExecutionModeEnum(mode.upper())
        act_enum = AuditActionEnum(action.upper())

        if mode_enum == ExecutionModeEnum.REAL:
            # Create audit record documenting the rejection before raising
            async with db_manager.session() as sess:
                audit_entry = AuditLog(
                    audit_id=f"AUD-REJ-{uuid.uuid4().hex[:8].upper()}",
                    timestamp=datetime.now(timezone.utc),
                    operator_id=operator_id,
                    action=act_enum,
                    object_type="DEVICE",
                    object_id=device_id,
                    previous_state="UNKNOWN",
                    new_state="REJECTED",
                    mode=mode_enum,
                    result="REJECTED_SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED",
                    reason=reason
                )
                sess.add(audit_entry)
                await sess.flush()
            raise PermissionError("SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED: Only SIMULATION mode is permitted.")

        async with db_manager.session() as sess:
            res = await sess.execute(select(Device).where(Device.id == device_id))
            dev = res.scalar_one_or_none()
            if not dev:
                raise ValueError(f"Device '{device_id}' does not exist.")

            prev_state = dev.security_state
            if act_enum == AuditActionEnum.ISOLATE_DEVICE:
                dev.security_state = "ISOLATED"
            elif act_enum == AuditActionEnum.QUARANTINE_ENDPOINT:
                dev.security_state = "QUARANTINED"
            elif act_enum == AuditActionEnum.MARK_DEVICE_AT_RISK:
                dev.security_state = "AT_RISK"
            elif act_enum == AuditActionEnum.INCREASE_SECURITY_LEVEL:
                dev.security_state = "ELEVATED"

            audit_entry = AuditLog(
                audit_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(timezone.utc),
                operator_id=operator_id,
                action=act_enum,
                object_type="DEVICE",
                object_id=device_id,
                previous_state=prev_state,
                new_state=dev.security_state,
                mode=mode_enum,
                result="SUCCESS",
                reason=reason
            )
            sess.add(audit_entry)
            await sess.flush()

            # Eagerly refresh objects before session close
            await sess.refresh(dev)
            await sess.refresh(audit_entry)
            return dev, audit_entry

dal = UnifiedRepository()