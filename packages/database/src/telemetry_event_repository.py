from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from packages.database.src.db_connection import db_manager

class TelemetryEventRepository:
    """Repository handling persistence for Telemetry, NetFlow, IDS, and Security Events."""

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
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.telemetry.create(
            data={
                "deviceId": device_id,
                "timestamp": ts,
                "cpuUsage": float(cpu_usage),
                "memoryUsage": float(memory_usage),
                "networkUtilization": float(network_utilization),
                "packetRate": float(packet_rate),
                "byteRate": float(byte_rate),
                "activeConnections": int(active_connections),
                "securityState": security_state,
                "riskScore": float(risk_score),
                "source": source
            }
        )

    @staticmethod
    async def get_device_telemetry_history(
        device_id: str,
        limit: int = 100,
        since_minutes: int = 60
    ) -> List[Any]:
        prisma = db_manager.client
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)

        return await prisma.telemetry.find_many(
            where={
                "deviceId": device_id,
                "timestamp": {"gte": cutoff}
            },
            order={"timestamp": "desc"},
            take=limit
        )

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
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.trafficflow.create(
            data={
                "timestamp": ts,
                "sourceIp": source_ip,
                "destinationIp": destination_ip,
                "sourcePort": int(source_port),
                "destinationPort": int(destination_port),
                "protocol": protocol.upper(),
                "packetCount": int(packet_count),
                "byteCount": int(byte_count),
                "flowDuration": float(flow_duration),
                "connectionCount": int(connection_count),
                "status": status,
                "sourceDeviceId": source_device_id,
                "destinationDeviceId": destination_device_id
            }
        )

    @staticmethod
    async def query_flows_by_protocol(
        protocol: str,
        limit: int = 50
    ) -> List[Any]:
        prisma = db_manager.client
        return await prisma.trafficflow.find_many(
            where={"protocol": protocol.upper()},
            order={"timestamp": "desc"},
            take=limit
        )

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
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.securityevent.upsert(
            where={"eventId": event_id},
            data={
                "create": {
                    "eventId": event_id,
                    "timestamp": ts,
                    "source": source,
                    "destination": destination,
                    "deviceId": device_id,
                    "protocol": protocol.upper(),
                    "port": port,
                    "eventType": event_type,
                    "severity": severity.upper(),
                    "detectionSource": detection_source,
                    "detectionType": detection_type,
                    "confidence": float(confidence),
                    "evidence": evidence,
                    "status": status
                },
                "update": {
                    "severity": severity.upper(),
                    "status": status,
                    "evidence": evidence
                }
            }
        )

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
    ) -> Any:
        prisma = db_manager.client
        ts = timestamp or datetime.now(timezone.utc)

        return await prisma.idsevent.create(
            data={
                "timestamp": ts,
                "source": source,
                "destination": destination,
                "protocol": protocol.upper(),
                "port": port,
                "signature": signature,
                "signatureId": int(signature_id),
                "severity": severity.upper(),
                "category": category,
                "sensor": sensor.upper(),
                "rawReference": raw_reference,
                "securityEventId": security_event_id
            }
        )

    @staticmethod
    async def list_ids_events(limit: int = 50) -> List[Any]:
        prisma = db_manager.client
        return await prisma.idsevent.find_many(
            order={"timestamp": "desc"},
            take=limit,
            include={"securityEvent": True}
        )

telemetry_event_repo = TelemetryEventRepository()