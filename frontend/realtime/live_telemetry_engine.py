from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
import uuid

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeEventEnvelope, CpuTelemetryPayload,
    MemoryTelemetryPayload, TrafficTelemetryPayload, ConnectionStatePayload
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager

class ConnectionLifecycleState(str, Enum):
    NEW = "NEW"
    CONNECTING = "CONNECTING"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    FAILED = "FAILED"

class DeviceLiveTelemetry(BaseModel):
    deviceId: str
    cpuUtilizationPct: float = 12.0
    memoryUsedMb: float = 2048.0
    memoryTotalMb: float = 16384.0
    memoryUtilizationPct: float = 12.5
    packetRateIn: float = 120.0
    packetRateOut: float = 115.0
    byteRateIn: float = 65536.0
    byteRateOut: float = 62400.0
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class LiveConnectionEntry(BaseModel):
    connectionId: str
    sourceDeviceId: str
    destinationDeviceId: str
    protocol: str = "TCP"
    sourcePort: int = 49152
    destinationPort: int = 443
    state: ConnectionLifecycleState = ConnectionLifecycleState.ESTABLISHED
    bytesTransferred: int = 4096
    packetsTransferred: int = 32
    openedTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class TelemetryAggregationSummary(BaseModel):
    totalRawEventsIngested: int
    aggregatedBroadcastsEmitted: int
    activeConnections: int
    newConnections: int
    failedConnections: int
    closedConnections: int
    averageCpuPct: float
    totalPacketRate: float
    totalByteRate: float

class LiveTelemetryEngine:
    """Coordinates sub-second telemetry ingestion, connection lifecycles, and 2D/3D synchronization."""

    def __init__(self, aggregation_window_events: int = 10):
        self.device_telemetry_registry: Dict[str, DeviceLiveTelemetry] = {}
        self.connection_registry: Dict[str, LiveConnectionEntry] = {}
        self.aggregation_window = aggregation_window_events
        self.raw_event_counter = 0
        self.broadcast_counter = 0
        self.connection_counts = {
            ConnectionLifecycleState.NEW: 0,
            ConnectionLifecycleState.CONNECTING: 0,
            ConnectionLifecycleState.ESTABLISHED: 0,
            ConnectionLifecycleState.CLOSING: 0,
            ConnectionLifecycleState.CLOSED: 0,
            ConnectionLifecycleState.FAILED: 0
        }
        self._initialize_baseline_telemetry()

    def _initialize_baseline_telemetry(self):
        for did in attack_path_graph.nodes.keys():
            self.device_telemetry_registry[did] = DeviceLiveTelemetry(deviceId=did)

    async def update_device_cpu(self, device_id: str, cpu_pct: float) -> RealtimeEventEnvelope:
        if device_id not in self.device_telemetry_registry:
            self.device_telemetry_registry[device_id] = DeviceLiveTelemetry(deviceId=device_id)

        tel = self.device_telemetry_registry[device_id]
        tel.cpuUtilizationPct = round(max(0.0, min(100.0, cpu_pct)), 2)
        tel.lastUpdated = datetime.now(timezone.utc).isoformat()
        self.raw_event_counter += 1

        # Synchronize with 3D device visual particle pulse
        if device_id in device_3d_renderer_engine.device_mesh_registry:
            mesh = device_3d_renderer_engine.device_mesh_registry[device_id]
            mesh.particlePulseRate = round(1.0 + (cpu_pct / 25.0), 2)

        payload = CpuTelemetryPayload(
            deviceId=device_id,
            cpuUtilizationPct=tel.cpuUtilizationPct,
            coreLoads=[tel.cpuUtilizationPct, round(tel.cpuUtilizationPct * 0.95, 2)]
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.CPU_UPDATE,
            payload=payload.model_dump(),
            device_id=device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        self.broadcast_counter += 1
        return env

    async def update_device_memory(self, device_id: str, memory_used_mb: float, total_mb: float = 16384.0) -> RealtimeEventEnvelope:
        if device_id not in self.device_telemetry_registry:
            self.device_telemetry_registry[device_id] = DeviceLiveTelemetry(deviceId=device_id)

        tel = self.device_telemetry_registry[device_id]
        tel.memoryUsedMb = round(memory_used_mb, 2)
        tel.memoryTotalMb = total_mb
        tel.memoryUtilizationPct = round((memory_used_mb / max(1.0, total_mb)) * 100.0, 2)
        tel.lastUpdated = datetime.now(timezone.utc).isoformat()
        self.raw_event_counter += 1

        payload = MemoryTelemetryPayload(
            deviceId=device_id,
            memoryUsedMb=tel.memoryUsedMb,
            memoryTotalMb=tel.memoryTotalMb,
            memoryUtilizationPct=tel.memoryUtilizationPct
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.MEMORY_UPDATE,
            payload=payload.model_dump(),
            device_id=device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        self.broadcast_counter += 1
        return env

    async def update_traffic_flow(
        self,
        source_device_id: str,
        destination_device_id: str,
        protocol: str = "HTTPS",
        packet_rate: float = 150.0,
        byte_rate: float = 76800.0
    ) -> RealtimeEventEnvelope:
        # Match link in 3D topology
        link_id = "CONN-FLOW-ACTIVE"
        for lid, l in link_3d_renderer_engine.link_registry.items():
            if (l.sourceDeviceId == source_device_id and l.destinationDeviceId == destination_device_id) or \
               (l.sourceDeviceId == destination_device_id and l.destinationDeviceId == source_device_id):
                link_id = lid
                l.trafficRateBps = byte_rate
                # Inject 3D particle
                link_3d_renderer_engine.inject_traffic_flow(lid, bytes_count=int(byte_rate / max(1.0, packet_rate)))
                break

        # Update node device telemetry
        if source_device_id in self.device_telemetry_registry:
            self.device_telemetry_registry[source_device_id].packetRateOut = packet_rate
            self.device_telemetry_registry[source_device_id].byteRateOut = byte_rate
        if destination_device_id in self.device_telemetry_registry:
            self.device_telemetry_registry[destination_device_id].packetRateIn = packet_rate
            self.device_telemetry_registry[destination_device_id].byteRateIn = byte_rate

        self.raw_event_counter += 1

        payload = TrafficTelemetryPayload(
            linkId=link_id,
            sourceDeviceId=source_device_id,
            destinationDeviceId=destination_device_id,
            protocol=protocol,
            packetsPerSecond=packet_rate,
            bytesPerSecond=byte_rate,
            activeConnections=self.connection_counts[ConnectionLifecycleState.ESTABLISHED] or 12
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.TRAFFIC_UPDATE,
            payload=payload.model_dump(),
            device_id=source_device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        self.broadcast_counter += 1
        return env

    async def update_connection_lifecycle(
        self,
        connection_id: str,
        source_device_id: str,
        destination_device_id: str,
        state: ConnectionLifecycleState,
        destination_port: int = 443
    ) -> RealtimeEventEnvelope:
        prev_state = None
        if connection_id in self.connection_registry:
            prev_state = self.connection_registry[connection_id].state
            if self.connection_counts[prev_state] > 0:
                self.connection_counts[prev_state] -= 1

        self.connection_registry[connection_id] = LiveConnectionEntry(
            connectionId=connection_id,
            sourceDeviceId=source_device_id,
            destinationDeviceId=destination_device_id,
            destinationPort=destination_port,
            state=state
        )
        self.connection_counts[state] += 1
        self.raw_event_counter += 1

        # Match link reachable state
        is_reachable = (state in (ConnectionLifecycleState.ESTABLISHED, ConnectionLifecycleState.NEW, ConnectionLifecycleState.CONNECTING))
        
        payload = ConnectionStatePayload(
            connectionId=connection_id,
            linkId=f"LINK-{source_device_id}-{destination_device_id}",
            status=state.value,
            isReachable=is_reachable,
            packetDropRatePct=100.0 if state == ConnectionLifecycleState.FAILED else 0.0
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.CONNECTION_UPDATE,
            payload=payload.model_dump(),
            device_id=source_device_id
        )
        await websocket_connection_manager.broadcast_envelope(env)
        self.broadcast_counter += 1
        return env

    def get_aggregated_summary(self) -> TelemetryAggregationSummary:
        devices = list(self.device_telemetry_registry.values())
        avg_cpu = sum(d.cpuUtilizationPct for d in devices) / max(1, len(devices))
        total_pkts = sum(d.packetRateIn + d.packetRateOut for d in devices)
        total_bytes = sum(d.byteRateIn + d.byteRateOut for d in devices)

        return TelemetryAggregationSummary(
            totalRawEventsIngested=self.raw_event_counter,
            aggregatedBroadcastsEmitted=self.broadcast_counter,
            activeConnections=self.connection_counts[ConnectionLifecycleState.ESTABLISHED],
            newConnections=self.connection_counts[ConnectionLifecycleState.NEW],
            failedConnections=self.connection_counts[ConnectionLifecycleState.FAILED],
            closedConnections=self.connection_counts[ConnectionLifecycleState.CLOSED],
            averageCpuPct=round(avg_cpu, 2),
            totalPacketRate=round(total_pkts, 2),
            totalByteRate=round(total_bytes, 2)
        )

live_telemetry_engine = LiveTelemetryEngine()