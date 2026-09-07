from typing import Dict, Any, Optional
from datetime import datetime, timezone

from packages.shared_types.src.telemetry import TelemetryMetricEvent
from packages.shared_types.src.events import SecurityEvent
from services.digital_twin.core.twin_core import DigitalTwinCore

class TwinSynchronizationEngine:
    """Consumes real-world telemetry and anomaly alerts to synchronize twin states."""

    def __init__(self, twin_core: DigitalTwinCore):
        self.twin = twin_core

    def ingest_metric_telemetry(self, event: TelemetryMetricEvent) -> Dict[str, Any]:
        """Processes operational telemetry metrics with strict entity validation."""
        device = self.twin.devices.get_device(event.device_id)
        if not device:
            raise KeyError(f"Ingestion rejected: Device ID '{event.device_id}' does not exist in twin registry.")

        # Update specific operational metric
        if event.metric == "packet_rate":
            device.current_state.network_state.packet_rate_pps = event.value
        elif event.metric == "byte_rate":
            device.current_state.network_state.byte_rate_bps = event.value
        elif event.metric == "cpu_usage":
            device.current_state.cpu_usage_pct = event.value
        elif event.metric == "memory_usage":
            device.current_state.memory_usage_pct = event.value
        elif event.metric == "active_connections":
            device.current_state.network_state.active_connections_count = int(event.value)
        elif event.metric == "latency":
            device.current_state.network_state.latency_ms = event.value

        device.current_state.last_updated = event.timestamp
        self.twin.topology.sync_device(device)

        return {
            "status": "TELEMETRY_SYNCHRONIZED",
            "device_id": event.device_id,
            "metric": event.metric,
            "value": event.value,
            "timestamp": event.timestamp
        }

    def ingest_anomaly_security_event(self, sec_event: SecurityEvent) -> Dict[str, Any]:
        """Closed-loop integration: Anomaly event triggers formal FSM degradation."""
        # Resolve target device by destination IP if device ID omitted
        target_device = None
        if sec_event.destination_device_id:
            target_device = self.twin.devices.get_device(sec_event.destination_device_id)
        
        if not target_device and sec_event.destination_ip:
            for d in self.twin.devices.list_devices():
                if any(iface.ip_address == sec_event.destination_ip for iface in d.interfaces):
                    target_device = d
                    break

        if not target_device:
            raise KeyError(f"Ingestion rejected: Destination '{sec_event.destination_ip or sec_event.destination_device_id}' unresolvable.")

        # Map security alert to state machine transition
        new_state = "COMPROMISED" if sec_event.severity == "CRITICAL" else "SUSPICIOUS"
        transition_record = self.twin.transition_security_state(
            device_id=target_device.id,
            new_state=new_state,
            trigger=sec_event.detection_source,
            reason=f"{sec_event.event_type} - {sec_event.details.get('description', 'Anomaly detection alert')}"
        )

        return {
            "status": "SECURITY_STATE_SYNCHRONIZED",
            "target_device_id": target_device.id,
            "new_state": new_state,
            "transition_logged": transition_record is not None,
            "current_risk_score": target_device.security_state_model.risk_score
        }