from typing import List, Optional, Any
from sqlalchemy import select, delete
from packages.database.src.db_connection import db_manager
from packages.database.src.models import Device
from packages.shared_types.src.network_device import NetworkDeviceModel

class DeviceRepository:
    """Repository handling CRUD operations for Network Twin Devices in PostgreSQL using SQLAlchemy."""

    @staticmethod
    async def upsert_device(device: NetworkDeviceModel) -> Device:
        primary_ip = device.ip or (device.ip_addresses[0] if device.ip_addresses else "0.0.0.0")

        async with db_manager.session() as sess:
            res = await sess.execute(select(Device).where(Device.id == device.id))
            db_dev = res.scalar_one_or_none()

            hostname_val = device.name or device.hostname or device.id
            dev_type = str(getattr(device.device_type, "value", device.device_type))
            net_zone = str(getattr(device.networkZone, "value", device.networkZone))
            ip_addrs = list(device.ip_addresses) if device.ip_addresses else ([primary_ip] if primary_ip != "0.0.0.0" else [])
            mac_addrs = list(getattr(device, "macAddresses", [])) if getattr(device, "macAddresses", None) else []
            sec_state = str(device.security_state)
            op_state = str(getattr(device, "currentState", "HEALTHY"))
            risk_val = float(getattr(device, "riskScore", 0.0))
            is_comp = bool(device.is_compromised)

            if not db_dev:
                db_dev = Device(
                    id=device.id,
                    hostname=hostname_val,
                    device_type=dev_type,
                    network_zone=net_zone,
                    primary_ip=primary_ip,
                    ip_addresses=ip_addrs,
                    mac_addresses=mac_addrs,
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
            return db_dev

    @staticmethod
    async def get_device_by_id(device_id: str) -> Optional[Device]:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Device).where(Device.id == device_id))
            return res.scalar_one_or_none()

    @staticmethod
    async def list_all_devices() -> List[Device]:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Device))
            return list(res.scalars().all())

device_repository = DeviceRepository()