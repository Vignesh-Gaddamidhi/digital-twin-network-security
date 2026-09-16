import json
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from packages.database.src.db_connection import db_manager
from packages.shared_types.src.network_device import NetworkDeviceModel

class DigitalTwinPersistenceRepository:
    """Repository managing structured relational persistence for the Network Digital Twin."""

    @staticmethod
    async def persist_device_aggregate(
        device: NetworkDeviceModel,
        interfaces: Optional[List[Dict[str, Any]]] = None,
        services: Optional[List[Dict[str, Any]]] = None,
        ports: Optional[List[Dict[str, Any]]] = None
    ) -> Any:
        """Persists a Device and its structured interfaces, services, and ports transactionally."""
        prisma = db_manager.client
        primary_ip = device.ip or (device.ip_addresses[0] if device.ip_addresses else "0.0.0.0")

        # 1. Upsert Device Root Record
        db_device = await prisma.device.upsert(
            where={"id": device.id},
            data={
                "create": {
                    "id": device.id,
                    "hostname": device.name or device.hostname or device.id,
                    "deviceType": str(getattr(device.device_type, "value", device.device_type)),
                    "networkZone": str(getattr(device.networkZone, "value", device.networkZone)),
                    "primaryIp": primary_ip,
                    "ipAddresses": device.ip_addresses or ([primary_ip] if primary_ip != "0.0.0.0" else []),
                    "macAddresses": getattr(device, "macAddresses", []) or [],
                    "operatingSystem": getattr(device, "operatingSystem", None),
                    "role": getattr(device, "role", None),
                    "securityState": str(device.security_state),
                    "operationalState": str(getattr(device, "currentState", "HEALTHY")),
                    "riskScore": float(getattr(device, "riskScore", 0.0)),
                    "isCompromised": bool(device.is_compromised)
                },
                "update": {
                    "hostname": device.name or device.hostname or device.id,
                    "securityState": str(device.security_state),
                    "operationalState": str(getattr(device, "currentState", "HEALTHY")),
                    "riskScore": float(getattr(device, "riskScore", 0.0)),
                    "isCompromised": bool(device.is_compromised)
                }
            }
        )

        # 2. Persist Interfaces
        if interfaces:
            for iface in interfaces:
                iname = iface.get("interface_name") or iface.get("interface_id") or "eth0"
                await prisma.deviceinterface.upsert(
                    where={"deviceId_interfaceName": {"deviceId": device.id, "interfaceName": iname}},
                    data={
                        "create": {
                            "deviceId": device.id,
                            "interfaceName": iname,
                            "macAddress": iface.get("mac_address"),
                            "ipAddress": iface.get("ip_address", primary_ip),
                            "subnet": iface.get("subnet", "255.255.255.0"),
                            "gateway": iface.get("gateway"),
                            "status": iface.get("status", "UP"),
                            "speed": iface.get("speed", "1Gbps")
                        },
                        "update": {
                            "ipAddress": iface.get("ip_address", primary_ip),
                            "status": iface.get("status", "UP")
                        }
                    }
                )

        # 3. Persist Services
        if services:
            for s in services:
                sname = s.get("name", "UNKNOWN")
                sport = int(s.get("port", 0))
                sproto = s.get("protocol", "TCP")
                await prisma.deviceservice.upsert(
                    where={"deviceId_name_port_protocol": {
                        "deviceId": device.id,
                        "name": sname,
                        "port": sport,
                        "protocol": sproto
                    }},
                    data={
                        "create": {
                            "deviceId": device.id,
                            "name": sname,
                            "port": sport,
                            "protocol": sproto,
                            "status": s.get("status", "RUNNING"),
                            "version": s.get("version", "1.0.0"),
                            "securityState": s.get("security_state", "NORMAL")
                        },
                        "update": {
                            "status": s.get("status", "RUNNING"),
                            "securityState": s.get("security_state", "NORMAL")
                        }
                    }
                )

        # 4. Persist Ports
        if ports:
            for p in ports:
                pnum = int(p.get("port_number", p.get("port", 0)))
                pproto = p.get("protocol", "TCP")
                pstate = p.get("state", "OPEN").upper()
                if pstate not in ["OPEN", "CLOSED", "FILTERED", "UNKNOWN"]:
                    pstate = "OPEN"
                await prisma.deviceport.upsert(
                    where={"deviceId_portNumber_protocol": {
                        "deviceId": device.id,
                        "portNumber": pnum,
                        "protocol": pproto
                    }},
                    data={
                        "create": {
                            "deviceId": device.id,
                            "portNumber": pnum,
                            "protocol": pproto,
                            "state": pstate,
                            "service": p.get("service"),
                            "exposure": p.get("exposure", "INTERNAL")
                        },
                        "update": {
                            "state": pstate,
                            "service": p.get("service")
                        }
                    }
                )

        return db_device

    @staticmethod
    async def persist_connection(
        connection_id: str,
        source_device_id: str,
        destination_device_id: str,
        protocol: str = "TCP",
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        status: str = "ACTIVE",
        connection_count: int = 1
    ) -> Any:
        """Persists a live network communication link."""
        prisma = db_manager.client
        now = datetime.now(timezone.utc)

        return await prisma.networkconnection.upsert(
            where={"id": connection_id},
            data={
                "create": {
                    "id": connection_id,
                    "sourceDeviceId": source_device_id,
                    "destinationDeviceId": destination_device_id,
                    "protocol": protocol,
                    "sourcePort": source_port,
                    "destinationPort": destination_port,
                    "status": status,
                    "connectionCount": connection_count,
                    "firstSeen": now,
                    "lastSeen": now
                },
                "update": {
                    "status": status,
                    "lastSeen": now,
                    "connectionCount": connection_count
                }
            }
        )

    @staticmethod
    async def persist_topology_edge(
        edge_id: str,
        source_device_id: str,
        destination_device_id: str,
        edge_type: str = "LOGICAL",
        protocol: str = "TCP",
        status: str = "ACTIVE",
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Persists a graph topology edge representing living adjacency."""
        prisma = db_manager.client

        return await prisma.topologyedge.upsert(
            where={"id": edge_id},
            data={
                "create": {
                    "id": edge_id,
                    "sourceDeviceId": source_device_id,
                    "destinationDeviceId": destination_device_id,
                    "edgeType": edge_type,
                    "protocol": protocol,
                    "status": status,
                    "weight": float(weight),
                    "metadata": json.dumps(metadata or {})
                },
                "update": {
                    "status": status,
                    "weight": float(weight),
                    "metadata": json.dumps(metadata or {})
                }
            }
        )

    @staticmethod
    async def get_device_aggregate(device_id: str) -> Optional[Any]:
        """Loads complete device entity with interfaces, services, ports, and edges."""
        prisma = db_manager.client
        return await prisma.device.find_unique(
            where={"id": device_id},
            include={
                "interfaces": True,
                "services": True,
                "ports": True,
                "outConnections": True,
                "inConnections": True,
                "outEdges": True,
                "inEdges": True
            }
        )

twin_persistence_repo = DigitalTwinPersistenceRepository()