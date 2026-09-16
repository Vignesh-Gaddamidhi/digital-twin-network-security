from typing import List, Optional, Dict, Any
from packages.database.src.db_connection import db_manager
from packages.shared_types.src.network_device import NetworkDeviceModel

class DeviceRepository:
    """Repository handling CRUD operations for Network Twin Devices in PostgreSQL."""

    @staticmethod
    async def upsert_device(device: NetworkDeviceModel) -> Any:
        """Persists or updates a live Digital Twin device node into PostgreSQL."""
        prisma = db_manager.client
        primary_ip = device.ip or "0.0.0.0"
        
        return await prisma.device.upsert(
            where={"id": device.id},
            data={
                "create": {
                    "id": device.id,
                    "hostname": device.name or device.hostname or device.id,
                    "deviceType": str(device.device_type.value if hasattr(device.device_type, "value") else device.device_type),
                    "networkZone": str(device.networkZone.value if hasattr(device.networkZone, "value") else device.networkZone),
                    "primaryIp": primary_ip,
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

    @staticmethod
    async def get_device_by_id(device_id: str) -> Optional[Any]:
        prisma = db_manager.client
        return await prisma.device.find_unique(where={"id": device_id})

    @staticmethod
    async def list_all_devices() -> List[Any]:
        prisma = db_manager.client
        return await prisma.device.find_many()

device_repository = DeviceRepository()