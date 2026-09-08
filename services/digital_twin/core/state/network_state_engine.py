from typing import Dict, List, Optional
from datetime import datetime, timezone

from packages.shared_types.src.network_state import (
    SessionStateEnum, DeviceNetworkMetricsModel, 
    ActiveConnectionSessionModel, DeviceConnectionStatsModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine

class ConnectionAlreadyExistsError(ValueError):
    pass

class ConnectionSessionNotFoundError(KeyError):
    pass

class NetworkStateEngine:
    """Manages real-time network utilization metrics and Layer 4 active/closed/failed sessions."""

    def __init__(self):
        self._device_metrics: Dict[str, DeviceNetworkMetricsModel] = {}
        self._sessions: Dict[str, ActiveConnectionSessionModel] = {}

    def _ensure_device_exists(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' does not exist in Device Registry.")

    # --- 1. Network Utilisation Tracking ---
    def updateNetworkMetrics(
        self,
        device_id: str,
        network_utilisation: float,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        packets_sent: int = 0,
        packets_received: int = 0
    ) -> DeviceNetworkMetricsModel:
        self._ensure_device_exists(device_id)
        if not (0.0 <= network_utilisation <= 100.0):
            raise ValueError(f"Network utilisation must be between 0.0 and 100.0%. Got {network_utilisation}")

        metrics = DeviceNetworkMetricsModel(
            networkUtilisation=round(network_utilisation, 2),
            bytesSent=bytes_sent,
            bytesReceived=bytes_received,
            packetsSent=packets_sent,
            packetsReceived=packets_received,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self._device_metrics[device_id] = metrics

        # Sync with main state_engine if active
        try:
            from services.digital_twin.core.state.state_engine import state_engine
            if device_id in state_engine._device_states:
                state_engine._device_states[device_id].performance.networkUtilisation = metrics.networkUtilisation
        except Exception:
            pass

        return metrics

    def getNetworkMetrics(self, device_id: str) -> DeviceNetworkMetricsModel:
        self._ensure_device_exists(device_id)
        if device_id not in self._device_metrics:
            self._device_metrics[device_id] = DeviceNetworkMetricsModel()
        return self._device_metrics[device_id]

    # --- 2. Dynamic Connection State Management ---
    def createConnectionState(self, session: ActiveConnectionSessionModel) -> ActiveConnectionSessionModel:
        self._ensure_device_exists(session.source)
        self._ensure_device_exists(session.destination)

        if session.id in self._sessions:
            raise ConnectionAlreadyExistsError(f"Session with ID '{session.id}' already exists.")

        # Ensure destination port is listening
        dst_dev = device_registry.getDevice(session.destination)
        if dst_dev and session.destinationPort not in dst_dev.ports:
            raise ValueError(f"Port {session.destinationPort} is not listening on destination device '{dst_dev.hostname}'.")

        now_ts = datetime.now(timezone.utc).isoformat()
        session.createdAt = now_ts
        session.lastSeen = now_ts
        self._sessions[session.id] = session

        # Sync connection state to GraphEngine edge if present
        self._sync_graph_edge(session)
        return session

    def updateConnectionState(self, session_id: str, status: SessionStateEnum) -> ActiveConnectionSessionModel:
        if session_id not in self._sessions:
            raise ConnectionSessionNotFoundError(f"Connection session '{session_id}' not found.")

        session = self._sessions[session_id]
        session.status = status
        session.lastSeen = datetime.now(timezone.utc).isoformat()

        # Reflect state change into graph edge
        self._sync_graph_edge(session)
        return session

    def closeConnection(self, session_id: str) -> ActiveConnectionSessionModel:
        return self.updateConnectionState(session_id, SessionStateEnum.CLOSED)

    def failConnection(self, session_id: str) -> ActiveConnectionSessionModel:
        return self.updateConnectionState(session_id, SessionStateEnum.FAILED)

    def _sync_graph_edge(self, session: ActiveConnectionSessionModel):
        """Synchronizes session operational state into GraphEngine edges without destroying the structure."""
        conns = connection_registry.getAllConnections(device_id=session.source)
        match = next((c for c in conns if (c.sourceDevice == session.source and c.destinationDevice == session.destination) or
                                          (c.sourceDevice == session.destination and c.destinationDevice == session.source)), None)
        if match:
            # Map SessionStateEnum to NetworkConnection status
            if session.status == SessionStateEnum.FAILED:
                from packages.shared_types.src.topology import ConnectionStatusEnum
                match.status = ConnectionStatusEnum.BLOCKED
                connection_registry.updateConnection(match)
            elif session.status == SessionStateEnum.ACTIVE:
                from packages.shared_types.src.topology import ConnectionStatusEnum
                match.status = ConnectionStatusEnum.ACTIVE
                connection_registry.updateConnection(match)

    def getActiveConnections(self) -> List[ActiveConnectionSessionModel]:
        return [s for s in self._sessions.values() if s.status == SessionStateEnum.ACTIVE]

    def getDeviceConnections(self, device_id: str) -> List[ActiveConnectionSessionModel]:
        self._ensure_device_exists(device_id)
        return [s for s in self._sessions.values() if s.source == device_id or s.destination == device_id]

    def getConnectionStats(self, device_id: str) -> DeviceConnectionStatsModel:
        self._ensure_device_exists(device_id)
        dev_sessions = self.getDeviceConnections(device_id)
        active_cnt = sum(1 for s in dev_sessions if s.status == SessionStateEnum.ACTIVE)
        closed_cnt = sum(1 for s in dev_sessions if s.status == SessionStateEnum.CLOSED)
        failed_cnt = sum(1 for s in dev_sessions if s.status == SessionStateEnum.FAILED)

        return DeviceConnectionStatsModel(
            deviceId=device_id,
            active=active_cnt,
            closed=closed_cnt,
            failed=failed_cnt,
            total=len(dev_sessions)
        )

    def clear(self):
        self._device_metrics.clear()
        self._sessions.clear()

network_state_engine = NetworkStateEngine()