from typing import Dict, List, Optional
from packages.shared_types.src.topology import ConnectionEntity

class ConnectionRegistry:
    """Tracks physical links, logical routes, and Layer 4 socket sessions."""

    def __init__(self):
        self._connections: Dict[str, ConnectionEntity] = {}

    def create_connection(self, conn: ConnectionEntity) -> ConnectionEntity:
        self._connections[conn.connection_id] = conn
        return conn

    def get_connection(self, connection_id: str) -> Optional[ConnectionEntity]:
        return self._connections.get(connection_id)

    def update_connection(self, conn: ConnectionEntity) -> ConnectionEntity:
        if conn.connection_id not in self._connections:
            raise KeyError(f"Connection {conn.connection_id} not found.")
        self._connections[conn.connection_id] = conn
        return conn

    def remove_connection(self, connection_id: str) -> bool:
        if connection_id in self._connections:
            del self._connections[connection_id]
            return True
        return False

    def get_device_connections(self, device_id: str) -> List[ConnectionEntity]:
        return [
            c for c in self._connections.values()
            if c.source_device == device_id or c.destination_device == device_id
        ]

    def list_connections(self) -> List[ConnectionEntity]:
        return list(self._connections.values())