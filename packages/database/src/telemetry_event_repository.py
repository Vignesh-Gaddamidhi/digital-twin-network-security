import uuid
from typing import List, Optional, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import Telemetry, TrafficFlow, SecurityEvent, IdsEvent

class TelemetryEventRepository:
    """SQLAlchemy 2.0 DAL for Telemetry, NetFlow, IDS, and Security Events."""

    # ==================== TELEMETRY ====================

    @staticmethod
    async def record_telemetry(
        device_id: str,
        cpu_usage: float,
        memory_usage: float,
        packet_rate: float,
        byte_rate: float,
        network_utilization: float = 0.0,
        active_connections: int = 0,
        security_state: str = "NORMAL",
        risk_score: float = 0.0,
        source: str = "TWIN_AGENT",
        timestamp: Optional[datetime] = None
    ) -> Telemetry:
        ts = timestamp or datetime.now(timezone.utc)
        async with db_manager.session() as sess:
            t = Telemetry(
                id=str(uuid.uuid4()),
                device_id=device_id,
                timestamp=ts,
                cpu_usage=float(cpu_usage),
                memory_usage=float(memory_usage),
                network_utilization=float(network_utilization),
                packet_rate=float(packet_rate),
                byte_rate=float(byte_rate),
                active_connections=int(active_connections),
                security_state=security_state,
                risk_score=float(risk_score),
                source=source
            )
            sess.add(t)
            await sess.flush()
            return t

    @staticmethod
    async def get_device_telemetry_history(
        device_id: str,
        limit: int = 100,
        since_minutes: int = 60
    ) -> List[Telemetry]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Telemetry)
                .where(Telemetry.device_id == device_id, Telemetry.timestamp >= cutoff)
                .order_by(Telemetry.timestamp.desc())
                .limit(limit)
            )
            return list(res.scalars().all())

    # ==================== TRAFFIC FLOWS ====================

    @staticmethod
    async def record_traffic_flow(
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str = "TCP",
        packet_count: int = 1,
        byte_count: int = 64,
        source_device_id: Optional[str] = None,
        destination_device_id: Optional[str] = None,
        flow_duration: float = 0.0,
        connection_count: int = 1,
        status: str = "ESTABLISHED",
        timestamp: Optional[datetime] = None
    ) -> TrafficFlow:
        ts = timestamp or datetime.now(timezone.utc)
        async with db_manager.session() as sess:
            flow = TrafficFlow(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=int(source_port),
                destination_port=int(destination_port),
                protocol=protocol.upper(),
                packet_count=int(packet_count),
                byte_count=int(byte_count),
                flow_duration=float(flow_duration),
                connection_count=int(connection_count),
                status=status,
                source_device_id=source_device_id,
                destination_device_id=destination_device_id
            )
            sess.add(flow)
            await sess.flush()
            return flow

    @staticmethod
    async def query_flows_by_protocol(
        protocol: str,
        limit: int = 50
    ) -> List[TrafficFlow]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(TrafficFlow)
                .where(TrafficFlow.protocol == protocol.upper())
                .order_by(TrafficFlow.timestamp.desc())
                .limit(limit)
            )
            return list(res.scalars().all())

    # ==================== SECURITY EVENTS ====================

    @staticmethod
    async def record_security_event(
        event_id: str,
        source: str,
        destination: str,
        event_type: str,
        severity: str = "INFO",
        detection_source: str = "SURICATA",
        detection_type: str = "SIGNATURE",
        device_id: Optional[str] = None,
        protocol: str = "TCP",
        port: Optional[int] = None,
        confidence: float = 1.0,
        evidence: Optional[str] = None,
        status: str = "UNRESOLVED",
        timestamp: Optional[datetime] = None
    ) -> SecurityEvent:
        ts = timestamp or datetime.now(timezone.utc)
        async with db_manager.session() as sess:
            res = await sess.execute(select(SecurityEvent).where(SecurityEvent.event_id == event_id))
            ev = res.scalar_one_or_none()
            if not ev:
                ev = SecurityEvent(
                    event_id=event_id,
                    timestamp=ts,
                    source=source,
                    destination=destination,
                    device_id=device_id,
                    protocol=protocol.upper(),
                    port=port,
                    event_type=event_type,
                    severity=severity.upper(),
                    detection_source=detection_source,
                    detection_type=detection_type,
                    confidence=float(confidence),
                    evidence=evidence,
                    status=status
                )
                sess.add(ev)
            else:
                ev.severity = severity.upper()
                ev.status = status
                ev.evidence = evidence
            await sess.flush()
            return ev

    # ==================== IDS EVENTS ====================

    @staticmethod
    async def record_ids_event(
        source: str,
        destination: str,
        signature: str,
        signature_id: int,
        severity: str = "HIGH",
        category: str = "ATTEMPTED_ADMIN",
        sensor: str = "SURICATA",
        protocol: str = "TCP",
        port: Optional[int] = None,
        raw_reference: Optional[str] = None,
        security_event_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> IdsEvent:
        ts = timestamp or datetime.now(timezone.utc)
        async with db_manager.session() as sess:
            ids_ev = IdsEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source=source,
                destination=destination,
                protocol=protocol.upper(),
                port=port,
                signature=signature,
                signature_id=int(signature_id),
                severity=severity.upper(),
                category=category,
                sensor=sensor.upper(),
                raw_reference=raw_reference,
                security_event_id=security_event_id
            )
            sess.add(ids_ev)
            await sess.flush()
            return ids_ev

    @staticmethod
    async def list_ids_events(limit: int = 50) -> List[IdsEvent]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(IdsEvent)
                .options(selectinload(IdsEvent.security_event))
                .order_by(IdsEvent.timestamp.desc())
                .limit(limit)
            )
            return list(res.scalars().all())

telemetry_event_repo = TelemetryEventRepository()