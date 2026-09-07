from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict

from packages.shared_types.src.events import SecurityEvent
from packages.shared_types.src.security import AttackMapping
from services.twin_engine.src.core.twin_state import twin_engine
from services.twin_engine.src.core.mitre_mapper import mitre_mapper

class SIEMCorrelationEngine:
    def __init__(self, correlation_window_sec: float = 30.0):
        self.correlation_window_sec = correlation_window_sec
        self.event_store: List[SecurityEvent] = []
        self.active_incidents: List[Dict[str, Any]] = []
        self.attack_mappings: List[Dict[str, Any]] = []
        self.flow_history: Dict[tuple, List[SecurityEvent]] = defaultdict(list)

    def resolve_device_id_by_ip(self, ip_address: str) -> Optional[str]:
        for device in twin_engine.node_registry.values():
            if any(iface.ip_address == ip_address for iface in device.interfaces):
                return device.id
        return None

    def ingest_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Ingests, enriches, correlates, and maps a security event to MITRE ATT&CK."""
        # 1. Topological Enrichment
        if not event.source_device_id:
            event.source_device_id = self.resolve_device_id_by_ip(event.source_ip)
        if not event.destination_device_id:
            event.destination_device_id = self.resolve_device_id_by_ip(event.destination_ip)

        src_node = twin_engine.node_registry.get(event.source_device_id) if event.source_device_id else None
        context = {
            "source_node_state": src_node.security_state if src_node else "UNKNOWN"
        }

        # 2. MITRE ATT&CK Technique Mapping
        mapping = mitre_mapper.map_event_to_attack(event, context=context)
        mapped_dict = None
        if mapping:
            mapped_dict = mapping.model_dump()
            self.attack_mappings.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                **mapped_dict
            })
            event.details["mitre_attack"] = mapped_dict

        self.event_store.append(event)
        flow_key = (event.source_ip, event.destination_ip)
        self.flow_history[flow_key].append(event)

        # 3. Update Digital Twin State directly
        if event.destination_device_id:
            dest_node = twin_engine.node_registry.get(event.destination_device_id)
            if dest_node:
                if event.severity == "CRITICAL":
                    twin_engine.degrade_cia(dest_node.id, "AVAILABILITY", 0.8)
                    twin_engine.degrade_cia(dest_node.id, "INTEGRITY", 0.75)
                    twin_engine.degrade_cia(dest_node.id, "CONFIDENTIALITY", 0.75)
                elif event.severity == "HIGH":
                    twin_engine.degrade_cia(dest_node.id, "CONFIDENTIALITY", 0.4)

        # 4. Correlation Logic
        correlated_incident = self.evaluate_correlation_rules(flow_key)

        return {
            "status": "INGESTED",
            "event_id": event.event_id,
            "source_device": event.source_device_id,
            "destination_device": event.destination_device_id,
            "mitre_attack": mapped_dict,
            "correlated_incident": correlated_incident
        }

    def evaluate_correlation_rules(self, flow_key: tuple) -> Optional[Dict[str, Any]]:
        recent_events = self.flow_history[flow_key]
        now = datetime.now(timezone.utc).timestamp()

        valid_events = []
        for e in recent_events:
            event_time = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")).timestamp()
            if now - event_time <= self.correlation_window_sec:
                valid_events.append(e)
        self.flow_history[flow_key] = valid_events

        event_types = [e.event_type for e in valid_events]

        has_recon = any("SCAN" in et or "PROBE" in et for et in event_types)
        has_exploit = any("EXPLOIT" in et or "COMMAND" in et or "SHELL" in et for et in event_types)

        if has_recon and has_exploit:
            incident = {
                "incident_id": f"INC-{len(self.active_incidents) + 1:04d}",
                "title": f"MULTI-STAGE ATTACK: Reconnaissance Pivot to Exploitation ({flow_key[0]} -> {flow_key[1]})",
                "severity": "CRITICAL",
                "attacker_ip": flow_key[0],
                "victim_ip": flow_key[1],
                "mitre_tactics": ["TA0043 (Reconnaissance)", "TA0002 (Execution)"],
                "events_involved": [e.event_id for e in valid_events],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            if not any(inc["title"] == incident["title"] for inc in self.active_incidents):
                self.active_incidents.append(incident)
                return incident

        return None

siem_engine = SIEMCorrelationEngine()