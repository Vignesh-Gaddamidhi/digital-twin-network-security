from typing import Dict, List, Optional
from datetime import datetime, timezone
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ConnectionStatusEnum
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class ConnectionAlreadyExistsError(ValueError):
    pass

class ConnectionNotFoundError(KeyError):
    pass

class NetworkConnectionRegistry:
    """Production registry managing NetworkConnectionModel instances with relational integrity."""

    def __init__(self):
        self._connections: Dict[str, NetworkConnectionModel] = {}

    def createConnection(self, conn: NetworkConnectionModel) -> NetworkConnectionModel:
        # 1. Duplicate check
        if conn.id in self._connections:
            raise ConnectionAlreadyExistsError(f"Connection with ID '{conn.id}' already exists.")

        # 2. Verify source device exists in DeviceRegistry
        if not device_registry.getDevice(conn.sourceDevice):
            raise DeviceNotFoundError(f"Source device '{conn.sourceDevice}' does not exist in registry.")

        # 3. Verify destination device exists in DeviceRegistry
        if not device_registry.getDevice(conn.destinationDevice):
            raise DeviceNotFoundError(f"Destination device '{conn.destinationDevice}' does not exist in registry.")

        # 4. Check for redundant parallel link
        for existing in self._connections.values():
            if (existing.sourceDevice == conn.sourceDevice and
                existing.destinationDevice == conn.destinationDevice and
                existing.protocol == conn.protocol and
                existing.destinationPort == conn.destinationPort and
                existing.status == ConnectionStatusEnum.ACTIVE and
                conn.status == ConnectionStatusEnum.ACTIVE):
                raise ConnectionAlreadyExistsError(
                    f"Active connection already exists between '{conn.sourceDevice}' and '{conn.destinationDevice}' on port {conn.destinationPort}."
                )

        conn.lastUpdated = datetime.now(timezone.utc).isoformat()
        self._connections[conn.id] = conn

        # Synchronize connection references onto device records
        src = device_registry.getDevice(conn.sourceDevice)
        if src and conn.id not in src.connections:
            src.connections.append(conn.id)

        dst = device_registry.getDevice(conn.destinationDevice)
        if dst and conn.id not in dst.connections:
            dst.connections.append(conn.id)

        return conn

    def getConnection(self, connection_id: str) -> Optional[NetworkConnectionModel]:
        return self._connections.get(connection_id)

    def getAllConnections(
        self,
        device_id: Optional[str] = None,
        conn_type: Optional[ConnectionTypeEnum] = None,
        status: Optional[ConnectionStatusEnum] = None
    ) -> List[NetworkConnectionModel]:
        results = list(self._connections.values())
        if device_id:
            results = [c for c in results if c.sourceDevice == device_id or c.destinationDevice == device_id]
        if conn_type:
            results = [c for c in results if c.connectionType == conn_type]
        if status:
            results = [c for c in results if c.status == status]
        return results

    def updateConnection(self, conn: NetworkConnectionModel) -> NetworkConnectionModel:
        if conn.id not in self._connections:
            raise ConnectionNotFoundError(f"Connection '{conn.id}' not found.")

        conn.lastUpdated = datetime.now(timezone.utc).isoformat()
        self._connections[conn.id] = conn
        return conn

    def deleteConnection(self, connection_id: str) -> bool:
        if connection_id not in self._connections:
            raise ConnectionNotFoundError(f"Connection '{connection_id}' not found.")

        conn = self._connections[connection_id]

        # Clean reference from devices
        src = device_registry.getDevice(conn.sourceDevice)
        if src and connection_id in src.connections:
            src.connections.remove(connection_id)

        dst = device_registry.getDevice(conn.destinationDevice)
        if dst and connection_id in dst.connections:
            dst.connections.remove(connection_id)

        del self._connections[connection_id]
        return True

    def count(self) -> int:
        return len(self._connections)

    def clear(self):
        self._connections.clear()

connection_registry = NetworkConnectionRegistry()