from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.topology_models import TopologyNodeState
from frontend.topology.three_d_filter_models import TopologyFilterCriteria, ViewModeEnum
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, DataFreshnessState, BackendHealthState,
    RealtimeEventEnvelope, TwinStateSnapshot
)

class DeviceStoreEntry(BaseModel):
    deviceId: str
    hostname: str
    deviceType: str
    zone: str
    securityState: str = "NORMAL"
    riskScore: float = 0.0
    cpuUtilizationPct: float = 12.0
    memoryUtilizationPct: float = 24.0
    packetRate: float = 120.0
    byteRate: float = 65536.0
    lastTelemetryTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    isTelemetryStale: bool = False

class NotificationEntry(BaseModel):
    notificationId: str
    timestamp: str
    level: str  # INFO, WARNING, CRITICAL
    title: str
    message: str

class RealtimeStoreEngine:
    """Universal state management engine governing 2D/3D synchronization and failure states."""

    DEVICE_STALE_THRESHOLD_SECONDS = 10.0
    HEARTBEAT_STALE_THRESHOLD_SECONDS = 2.5

    def __init__(self):
        self.connectionState = RealtimeConnectionState.DISCONNECTED
        self.backendState = BackendHealthState.HEALTHY
        self.dataFreshness = DataFreshnessState.UNKNOWN
        self.lastEventTimestamp: Optional[str] = None
        self.lastHeartbeatTimestamp: Optional[str] = None
        self.lastAppliedSequenceNumber: int = 0
        self.reconnectAttempts: int = 0

        # Primary Domain Entities
        self.devices: Dict[str, DeviceStoreEntry] = {}
        self.connections: List[Dict[str, Any]] = []
        self.trafficStats: Dict[str, Any] = {"packetRate": 0.0, "byteRate": 0.0, "activeConnections": 0}
        self.threats: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.predictions: Dict[str, Any] = {}
        self.risks: Dict[str, Any] = {}
        self.attackPaths: List[Dict[str, Any]] = []
        self.simulations: Dict[str, Any] = {}
        self.earlyWarnings: Dict[str, Any] = {}

        # Viewport, Selection, and Filter Persistence
        self.activeViewMode: ViewModeEnum = ViewModeEnum.VIEW_3D
        self.selectedDeviceId: Optional[str] = None
        self.activeFilters: TopologyFilterCriteria = TopologyFilterCriteria()

        # Deduplication & Notification Logging
        self.processedEventIds: Set[str] = set()
        self.notifications: List[NotificationEntry] = []
        self.maxNotificationBuffer = 50

    def apply_snapshot(self, snapshot: TwinStateSnapshot):
        """Initializes or reconciles entire client state from a complete TwinStateSnapshot."""
        self.connectionState = RealtimeConnectionState.CONNECTED
        self.backendState = snapshot.backendHealth
        self.dataFreshness = DataFreshnessState.FRESH
        self.lastAppliedSequenceNumber = snapshot.sequenceNumber
        self.lastHeartbeatTimestamp = datetime.now(timezone.utc).isoformat()
        self.reconnectAttempts = 0

        # Populate devices
        self.devices.clear()
        for d in snapshot.devices:
            did = d["deviceId"]
            self.devices[did] = DeviceStoreEntry(
                deviceId=did,
                hostname=d.get("hostname", did),
                deviceType=d.get("deviceType", "server"),
                zone=d.get("zone", "INTERNAL"),
                securityState=d.get("securityState", "NORMAL"),
                riskScore=d.get("riskScore", 0.0)
            )

        self.connections = list(snapshot.connections)
        self.trafficStats = dict(snapshot.traffic)
        self.threats = list(snapshot.threats)
        self.alerts = list(snapshot.alerts)
        self.predictions = dict(snapshot.predictions)
        self.risks = dict(snapshot.risks)
        self.attackPaths = list(snapshot.attackPaths)
        self.simulations = dict(snapshot.simulation)
        self.earlyWarnings = dict(snapshot.earlyWarnings)

    def apply_event_envelope(self, envelope: RealtimeEventEnvelope) -> bool:
        """Applies incremental delta event frames with strict ordering and deduplication."""
        # 1. Idempotency filter: reject duplicates or past sequences
        if envelope.eventId in self.processedEventIds or envelope.sequenceNumber <= self.lastAppliedSequenceNumber:
            return False

        self.processedEventIds.add(envelope.eventId)
        self.lastAppliedSequenceNumber = envelope.sequenceNumber
        self.lastEventTimestamp = envelope.timestamp

        etype = envelope.eventType
        p = envelope.payload

        # Dispatch state mutation
        if etype == RealtimeEventType.HEARTBEAT:
            self.lastHeartbeatTimestamp = datetime.now(timezone.utc).isoformat()
            self.dataFreshness = DataFreshnessState.FRESH

        elif etype == RealtimeEventType.DEVICE_STATE_UPDATE:
            did = p.get("deviceId")
            if did in self.devices:
                self.devices[did].securityState = p.get("newState", self.devices[did].securityState)
                self.devices[did].lastTelemetryTimestamp = datetime.now(timezone.utc).isoformat()
                self.devices[did].isTelemetryStale = False

        elif etype == RealtimeEventType.CPU_UPDATE:
            did = p.get("deviceId")
            if did in self.devices:
                self.devices[did].cpuUtilizationPct = p.get("cpuUtilizationPct", self.devices[did].cpuUtilizationPct)
                self.devices[did].lastTelemetryTimestamp = datetime.now(timezone.utc).isoformat()
                self.devices[did].isTelemetryStale = False

        elif etype == RealtimeEventType.MEMORY_UPDATE:
            did = p.get("deviceId")
            if did in self.devices:
                self.devices[did].memoryUtilizationPct = p.get("memoryUtilizationPct", self.devices[did].memoryUtilizationPct)
                self.devices[did].lastTelemetryTimestamp = datetime.now(timezone.utc).isoformat()
                self.devices[did].isTelemetryStale = False

        elif etype == RealtimeEventType.TRAFFIC_UPDATE:
            self.trafficStats["packetRate"] = p.get("packetsPerSecond", 0.0)
            self.trafficStats["byteRate"] = p.get("bytesPerSecond", 0.0)
            self.trafficStats["activeConnections"] = p.get("activeConnections", 0)

        elif etype == RealtimeEventType.THREAT_UPDATE:
            self.threats.append(p)
            self._add_notification("WARNING", "Threat Detected", f"{p.get('eventType')} detected on {p.get('targetDeviceId')}")

        elif etype == RealtimeEventType.ALERT_UPDATE:
            self.alerts.append(p)
            if p.get("severity") in ("CRITICAL", RiskLevelTier.CRITICAL.value):
                self._add_notification("CRITICAL", "Critical Security Alert", f"{p.get('eventType')} on {p.get('destinationDevice')}")

        elif etype == RealtimeEventType.PREDICTION_UPDATE:
            did = p.get("targetDeviceId")
            self.predictions[did] = p

        elif etype == RealtimeEventType.RISK_UPDATE:
            did = p.get("targetDeviceId")
            score = p.get("compositeRiskScore", 0.0)
            self.risks[did] = p
            if did in self.devices:
                self.devices[did].riskScore = score
            if score >= 80.0:
                self._add_notification("CRITICAL", "Elevated Risk Tier", f"{did} reached CRITICAL risk score {score}")

        elif etype == RealtimeEventType.ATTACK_PATH_UPDATE:
            self.attackPaths = [p]
            self._add_notification("CRITICAL", "Attack Path Discovered", f"Traversing chain: {' -> '.join(p.get('nodeSequence', []))}")

        elif etype == RealtimeEventType.EARLY_WARNING_UPDATE:
            did = p.get("targetDeviceId")
            self.earlyWarnings[did] = p

        elif etype == RealtimeEventType.RESPONSE_UPDATE:
            did = p.get("affectedDevice")
            new_st = p.get("newState")
            if did in self.devices:
                self.devices[did].securityState = new_st
            # Sever attack path if host is isolated
            if new_st in ("ISOLATED", "QUARANTINED"):
                for ap in self.attackPaths:
                    if did in ap.get("nodeSequence", []):
                        ap["reachability"] = "BLOCKED"
                        ap["status"] = "BLOCKED"
            self._add_notification("INFO", "Defensive Action Simulated", f"[{p.get('action')}] applied to {did}. State: {new_st}")

        elif etype == RealtimeEventType.ERROR:
            self.backendState = BackendHealthState.BACKEND_ERROR
            self._add_notification("CRITICAL", "Backend Error", f"[{p.get('errorCode')}] {p.get('errorMessage')}")

        return True

    def _add_notification(self, level: str, title: str, message: str):
        notif = NotificationEntry(
            notificationId=f"NTF-{len(self.notifications) + 1}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            title=title,
            message=message
        )
        self.notifications.insert(0, notif)
        if len(self.notifications) > self.maxNotificationBuffer:
            self.notifications.pop()

    def evaluate_staleness(self):
        """Audits both global connection pulse age and individual device telemetry timestamps."""
        now = datetime.now(timezone.utc)

        # 1. Global Heartbeat Freshness
        if self.lastHeartbeatTimestamp:
            hb_dt = datetime.fromisoformat(self.lastHeartbeatTimestamp)
            if (now - hb_dt).total_seconds() > self.HEARTBEAT_STALE_THRESHOLD_SECONDS:
                self.dataFreshness = DataFreshnessState.STALE
            else:
                self.dataFreshness = DataFreshnessState.FRESH

        # 2. Per-Device Telemetry Freshness
        for did, dev in self.devices.items():
            if dev.lastTelemetryTimestamp:
                dev_dt = datetime.fromisoformat(dev.lastTelemetryTimestamp)
                dev.isTelemetryStale = (now - dev_dt).total_seconds() > self.DEVICE_STALE_THRESHOLD_SECONDS

    def select_device(self, device_id: Optional[str]):
        """Sets active inspection target; persists seamlessly across 2D/3D switches."""
        self.selectedDeviceId = device_id

    def get_selected_device_details(self) -> Optional[DeviceStoreEntry]:
        if self.selectedDeviceId and self.selectedDeviceId in self.devices:
            return self.devices[self.selectedDeviceId]
        return None

    def set_active_filters(self, filters: TopologyFilterCriteria):
        """Sets persistent filter criteria; preserved during viewport switches."""
        self.activeFilters = filters

realtime_store_engine = RealtimeStoreEngine()