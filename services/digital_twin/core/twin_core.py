from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from services.twin_engine.src.core.twin_state import DeviceEntity
from packages.shared_types.src.topology import ConnectionEntity, TopologyValidationResult
from packages.shared_types.src.security import VulnerabilityEntity
from packages.shared_types.src.state import StateTransitionRecord

from services.digital_twin.core.devices.device_registry import DeviceRegistry
from services.digital_twin.core.connections.connection_registry import ConnectionRegistry
from services.digital_twin.core.topology.topology_engine import TopologyEngine
from services.digital_twin.core.state.state_engine import StateEngine
from services.digital_twin.core.vulnerabilities.vulnerability_engine import VulnerabilityEngine
from services.twin_engine.src.core.risk_engine import risk_engine

class DigitalTwinCore:
    """Core orchestrator coordinating registries, topology, state, and vulnerability engines."""

    def __init__(self, network_name: str = "LAB-NETWORK"):
        self.network_name = network_name
        self.devices = DeviceRegistry()
        self.connections = ConnectionRegistry()
        self.topology = TopologyEngine()
        self.state = StateEngine()
        self.vulns = VulnerabilityEngine()

    def register_device(self, device: DeviceEntity) -> DeviceEntity:
        self.vulns.calculate_exposure(device)
        d = self.devices.create_device(device)
        self.topology.sync_device(d)
        risk_engine.calculate_node_risk(d)
        return d

    def register_connection(self, conn: ConnectionEntity) -> ConnectionEntity:
        c = self.connections.create_connection(conn)
        self.topology.sync_connection(c)
        return c

    def update_device_health(self, device_id: str, cpu_pct: float, mem_pct: float, pps: float, bps: float, status: str = "ONLINE"):
        dev = self.devices.get_device(device_id)
        if not dev:
            return None
        res = self.state.update_operational_state(dev, cpu_pct, mem_pct, pps, bps, status)
        self.topology.sync_device(dev)
        return res

    def transition_security_state(self, device_id: str, new_state: str, trigger: str, reason: str) -> Optional[StateTransitionRecord]:
        dev = self.devices.get_device(device_id)
        if not dev:
            return None
        rec = self.state.update_security_state(dev, new_state, trigger, reason)
        if rec:
            self.topology.sync_device(dev)
            risk_engine.calculate_node_risk(dev)
        return rec

    def patch_vulnerability(self, device_id: str, vuln_id: str) -> bool:
        dev = self.devices.get_device(device_id)
        if not dev:
            return False
        success = self.vulns.update_vulnerability_status(dev, vuln_id, "PATCHED")
        if success:
            self.vulns.calculate_exposure(dev)
            risk_engine.calculate_node_risk(dev)
        return success

    def find_path(self, src_id: str, dst_id: str) -> TopologyValidationResult:
        device_names = {d.id: d.hostname for d in self.devices.list_devices()}
        return self.topology.find_shortest_path(src_id, dst_id, device_names)

    def generate_snapshot_text(self) -> str:
        all_devs = self.devices.list_devices()
        online_count = sum(1 for d in all_devs if d.current_state.status == "ONLINE")
        alert_count = sum(len(d.security_state_model.active_alerts) for d in all_devs)

        lines = [
            "============================================================",
            "                 DIGITAL TWIN SNAPSHOT                      ",
            "============================================================",
            f"Network: {self.network_name}",
            f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Devices: {len(all_devs)} | Online: {online_count} | Total Alerts: {alert_count}",
            "------------------------------------------------------------"
        ]

        for d in all_devs:
            ip = d.interfaces[0].ip_address if d.interfaces else "N/A"
            services_str = ", ".join(d.services) if d.services else "None"
            ports_str = ", ".join(str(p) for p in d.open_ports) if d.open_ports else "None"
            open_vulns = [v.cve_id for v in d.vulnerabilities if v.status == "OPEN"]
            vulns_str = ", ".join(open_vulns) if open_vulns else "None"

            lines.append(f"\n{d.hostname.upper()} ({d.id})")
            lines.append(f" ├── IP         : {ip}")
            lines.append(f" ├── Type       : {d.type} ({d.role})")
            lines.append(f" ├── Exposure   : {d.attack_surface.exposure_tier} ({d.attack_surface.accessibility})")
            lines.append(f" ├── Services   : {services_str}")
            lines.append(f" ├── Ports      : {ports_str}")
            lines.append(f" ├── Active CVEs: {vulns_str}")
            lines.append(f" ├── State      : {d.current_state.status} (CPU: {d.current_state.cpu_usage_pct}%)")
            lines.append(f" └── Security   : {d.security_state_model.security_status} (Risk: {d.security_state_model.risk_score})")

        lines.append("\n============================================================")
        return "\n".join(lines)