from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine
from frontend.simulations.simulation_control_engine import simulation_control_engine
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, DataFreshnessState, BackendHealthState,
    RealtimeEventEnvelope, TwinStateSnapshot, HeartbeatPayload, ErrorPayload
)

class RealtimeEventManager:
    """Manages real-time event sequencing, snapshot collation, latency timestamps, and freshness tracking."""

    STALE_THRESHOLD_SECONDS = 2.0

    def __init__(self, initial_sequence: int = 1000):
        self.current_sequence = initial_sequence
        self.last_heartbeat_timestamp = datetime.now(timezone.utc)
        self.connection_state = RealtimeConnectionState.CONNECTED
        self.backend_health = BackendHealthState.HEALTHY
        self.recent_events_buffer: List[RealtimeEventEnvelope] = []
        self.max_buffer_size = 200

    def get_next_sequence_number(self) -> int:
        self.current_sequence += 1
        return self.current_sequence

    def build_envelope(
        self,
        event_type: RealtimeEventType,
        payload: Dict[str, Any],
        device_id: Optional[str] = None,
        simulation_id: Optional[str] = None,
        source: str = "CANONICAL_DIGITAL_TWIN"
    ) -> RealtimeEventEnvelope:
        now_ts = datetime.now(timezone.utc).isoformat()
        seq = self.get_next_sequence_number()
        
        envelope = RealtimeEventEnvelope(
            eventType=event_type,
            timestamp=now_ts,
            receivedTimestamp=now_ts,
            processedTimestamp=now_ts,
            sequenceNumber=seq,
            simulationId=simulation_id or simulation_control_engine.live_state.reproducibility.simulationId,
            source=source,
            deviceId=device_id,
            payload=payload,
            metadata={"protocolVersion": "2.0-realtime", "bufferedIndex": len(self.recent_events_buffer)}
        )

        self.recent_events_buffer.append(envelope)
        if len(self.recent_events_buffer) > self.max_buffer_size:
            self.recent_events_buffer.pop(0)

        if event_type == RealtimeEventType.HEARTBEAT:
            self.last_heartbeat_timestamp = datetime.now(timezone.utc)

        return envelope

    def compute_freshness_state(self) -> Tuple[DataFreshnessState, float]:
        delta_sec = (datetime.now(timezone.utc) - self.last_heartbeat_timestamp).total_seconds()
        if delta_sec < 0:
            return DataFreshnessState.UNKNOWN, 0.0
        elif delta_sec <= self.STALE_THRESHOLD_SECONDS:
            return DataFreshnessState.FRESH, round(delta_sec, 3)
        return DataFreshnessState.STALE, round(delta_sec, 3)

    def detect_sequence_gap(self, last_seen_sequence: int, incoming_sequence: int) -> bool:
        """Returns True if a packet drop or ordering gap occurred."""
        return incoming_sequence != (last_seen_sequence + 1)

    def generate_full_twin_snapshot(self) -> TwinStateSnapshot:
        """Constructs a complete state snapshot of the canonical Twin."""
        twin_graph_synchronizer.full_synchronization()
        freshness, _ = self.compute_freshness_state()
        seq = self.get_next_sequence_number()

        # Extract Devices
        devices_list = []
        for did, node in attack_path_graph.nodes.items():
            devices_list.append({
                "deviceId": did,
                "hostname": node.hostname,
                "deviceType": node.deviceType,
                "zone": node.zone,
                "ipAddresses": node.ipAddresses,
                "securityState": node.securityState,
                "riskScore": node.riskScore,
                "vulnerabilities": node.vulnerabilities,
                "isCriticalAsset": (node.assetCriticality in ("HIGH", "CRITICAL") or "DB" in did)
            })

        # Extract Connections
        conns_list = []
        for eid, edge in attack_path_graph.edges.items():
            conns_list.append({
                "linkId": eid,
                "sourceDevice": edge.sourceNode,
                "destinationDevice": edge.destinationNode,
                "protocol": edge.protocol,
                "destinationPort": edge.destinationPort,
                "status": "ACTIVE" if edge.reachable else "BLOCKED",
                "isReachable": edge.reachable
            })

        # Extract Simulation State
        sim_state = simulation_control_engine.live_state

        # Extract Attack Paths
        cached = getattr(master_attack_path_orchestrator, "cached_master_analysis", None)
        analysis = cached or master_attack_path_orchestrator.run_master_analysis("CLIENT-01", "DB-01")
        paths_list = [p.model_dump() for p in analysis.rankedPaths]

        return TwinStateSnapshot(
            sequenceNumber=seq,
            connectionState=self.connection_state,
            freshness=freshness,
            backendHealth=self.backend_health,
            devices=devices_list,
            connections=conns_list,
            topology={"nodeCount": len(devices_list), "edgeCount": len(conns_list)},
            traffic={"packetsPerSecond": sim_state.currentPacketsPerSec, "activeConnections": 42},
            threats=[],
            alerts=[],
            predictions={"activeForecast": sim_state.predictedThreatProb},
            risks={"networkRiskScore": sim_state.networkRiskScore},
            attackPaths=paths_list,
            simulation=sim_state.model_dump(),
            earlyWarnings={"leadTimeSeconds": 42, "status": "WATCH"}
        )

realtime_event_manager = RealtimeEventManager()