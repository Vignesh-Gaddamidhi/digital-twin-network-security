import json
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select, delete
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import (
    Device, DeviceInterface, DeviceService, DevicePort,
    NetworkConnection, TopologyEdge, PortStateEnum
)
from packages.shared_types.src.network_device import NetworkDeviceModel

class DigitalTwinPersistenceRepository:
    """Repository managing structured relational persistence for the Network Digital Twin using SQLAlchemy."""

    @staticmethod
    async def persist_device_aggregate(
        device: NetworkDeviceModel,
        interfaces: Optional[List[Dict[str, Any]]] = None,
        services: Optional[List[Dict[str, Any]]] = None,
        ports: Optional[List[Dict[str, Any]]] = None
    ) -> Device:
        """Persists a Device and its structured interfaces, services, and ports transactionally."""
        primary_ip = getattr(device, "ip", None) or (device.ip_addresses[0] if getattr(device, "ip_addresses", None) else "0.0.0.0")

        async with db_manager.session() as sess:
            res = await sess.execute(select(Device).where(Device.id == device.id))
            db_dev = res.scalar_one_or_none()

            hostname_val = getattr(device, "name", None) or getattr(device, "hostname", None) or device.id
            dev_type = str(getattr(getattr(device, "device_type", None), "value", getattr(device, "device_type", "SERVER")))
            net_zone = str(getattr(getattr(device, "networkZone", None), "value", getattr(device, "networkZone", "DMZ")))
            ip_addrs = list(device.ip_addresses) if getattr(device, "ip_addresses", None) else ([primary_ip] if primary_ip != "0.0.0.0" else [])
            mac_addrs = list(getattr(device, "macAddresses", [])) if getattr(device, "macAddresses", None) else []
            os_val = getattr(device, "operatingSystem", None)
            role_val = getattr(device, "role", None)
            sec_state = str(getattr(device, "security_state", "NORMAL"))
            op_state = str(getattr(device, "currentState", "HEALTHY"))
            risk_val = float(getattr(device, "riskScore", 0.0))
            is_comp = bool(getattr(device, "is_compromised", False))

            if not db_dev:
                db_dev = Device(
                    id=device.id,
                    hostname=hostname_val,
                    device_type=dev_type,
                    network_zone=net_zone,
                    primary_ip=primary_ip,
                    ip_addresses=ip_addrs,
                    mac_addresses=mac_addrs,
                    operating_system=os_val,
                    role=role_val,
                    security_state=sec_state,
                    operational_state=op_state,
                    risk_score=risk_val,
                    is_compromised=is_comp
                )
                sess.add(db_dev)
            else:
                db_dev.hostname = hostname_val
                db_dev.device_type = dev_type
                db_dev.network_zone = net_zone
                db_dev.primary_ip = primary_ip
                db_dev.ip_addresses = ip_addrs
                db_dev.mac_addresses = mac_addrs
                db_dev.security_state = sec_state
                db_dev.operational_state = op_state
                db_dev.risk_score = risk_val
                db_dev.is_compromised = is_comp

            await sess.flush()

            # 2. Persist Interfaces
            if interfaces:
                for iface in interfaces:
                    iname = iface.get("interface_name") or iface.get("interface_id") or "eth0"
                    i_res = await sess.execute(
                        select(DeviceInterface).where(
                            DeviceInterface.device_id == device.id,
                            DeviceInterface.interface_name == iname
                        )
                    )
                    db_iface = i_res.scalar_one_or_none()
                    if not db_iface:
                        db_iface = DeviceInterface(
                            id=str(uuid.uuid4()),
                            device_id=device.id,
                            interface_name=iname,
                            mac_address=iface.get("mac_address"),
                            ip_address=iface.get("ip_address", primary_ip),
                            subnet=iface.get("subnet", "255.255.255.0"),
                            gateway=iface.get("gateway"),
                            status=iface.get("status", "UP"),
                            speed=iface.get("speed", "10Gbps")
                        )
                        sess.add(db_iface)
                    else:
                        db_iface.ip_address = iface.get("ip_address", primary_ip)
                        db_iface.status = iface.get("status", "UP")

            # 3. Persist Services
            if services:
                for s in services:
                    sname = s.get("name", "UNKNOWN")
                    sport = int(s.get("port", 0))
                    sproto = s.get("protocol", "TCP")
                    s_res = await sess.execute(
                        select(DeviceService).where(
                            DeviceService.device_id == device.id,
                            DeviceService.name == sname,
                            DeviceService.port == sport,
                            DeviceService.protocol == sproto
                        )
                    )
                    db_srv = s_res.scalar_one_or_none()
                    if not db_srv:
                        db_srv = DeviceService(
                            id=str(uuid.uuid4()),
                            device_id=device.id,
                            name=sname,
                            port=sport,
                            protocol=sproto,
                            status=s.get("status", "RUNNING"),
                            version=s.get("version", "1.0.0"),
                            security_state=s.get("security_state", "NORMAL")
                        )
                        sess.add(db_srv)
                    else:
                        db_srv.status = s.get("status", "RUNNING")
                        db_srv.security_state = s.get("security_state", "NORMAL")

            # 4. Persist Ports
            if ports:
                for p in ports:
                    pnum = int(p.get("port_number", p.get("port", 0)))
                    pproto = p.get("protocol", "TCP")
                    raw_state = p.get("state", "OPEN").upper()
                    try:
                        pstate_enum = PortStateEnum(raw_state)
                    except Exception:
                        pstate_enum = PortStateEnum.OPEN

                    p_res = await sess.execute(
                        select(DevicePort).where(
                            DevicePort.device_id == device.id,
                            DevicePort.port_number == pnum,
                            DevicePort.protocol == pproto
                        )
                    )
                    db_p = p_res.scalar_one_or_none()
                    if not db_p:
                        db_p = DevicePort(
                            id=str(uuid.uuid4()),
                            device_id=device.id,
                            port_number=pnum,
                            protocol=pproto,
                            state=pstate_enum,
                            service=p.get("service"),
                            exposure=p.get("exposure", "INTERNAL")
                        )
                        sess.add(db_p)
                    else:
                        db_p.state = pstate_enum
                        db_p.service = p.get("service")

            await sess.flush()
            return db_dev

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
    ) -> NetworkConnection:
        """Persists a live network communication link."""
        now = datetime.now(timezone.utc)
        async with db_manager.session() as sess:
            res = await sess.execute(select(NetworkConnection).where(NetworkConnection.id == connection_id))
            conn = res.scalar_one_or_none()

            if not conn:
                conn = NetworkConnection(
                    id=connection_id,
                    source_device_id=source_device_id,
                    destination_device_id=destination_device_id,
                    protocol=protocol,
                    source_port=source_port,
                    destination_port=destination_port,
                    status=status,
                    connection_count=connection_count,
                    first_seen=now,
                    last_seen=now
                )
                sess.add(conn)
            else:
                conn.status = status
                conn.last_seen = now
                conn.connection_count = connection_count

            await sess.flush()
            return conn

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
    ) -> TopologyEdge:
        """Persists a graph topology edge representing living adjacency."""
        async with db_manager.session() as sess:
            res = await sess.execute(select(TopologyEdge).where(TopologyEdge.id == edge_id))
            edge = res.scalar_one_or_none()

            if not edge:
                edge = TopologyEdge(
                    id=edge_id,
                    source_device_id=source_device_id,
                    destination_device_id=destination_device_id,
                    edge_type=edge_type,
                    protocol=protocol,
                    status=status,
                    weight=float(weight),
                    metadata_json=metadata or {}
                )
                sess.add(edge)
            else:
                edge.status = status
                edge.weight = float(weight)
                edge.metadata_json = metadata or {}

            await sess.flush()
            return edge

    @staticmethod
    async def get_device_aggregate(device_id: str) -> Optional[Device]:
        """Loads complete device entity with interfaces, services, and ports eager-loaded."""
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Device)
                .where(Device.id == device_id)
                .options(
                    selectinload(Device.interfaces),
                    selectinload(Device.services),
                    selectinload(Device.ports),
                    selectinload(Device.out_connections),
                    selectinload(Device.in_connections),
                    selectinload(Device.out_edges),
                    selectinload(Device.in_edges)
                )
            )
            return res.scalar_one_or_none()

twin_persistence_repo = DigitalTwinPersistenceRepository()