from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from packages.shared_types.src.state_integration import (
    UniversalStateEvent, StateEventSourceEnum, SupportedMetricEnum,
    DualSourceDeviceState, SourcePartitionStateModel, EffectiveTwinStateModel,
    StateAuditHistoryEntry
)
from packages.shared_types.src.device_state import OperationalStatusEnum
from packages.shared_types.src.performance import PerformanceLevelEnum
from packages.shared_types.src.security_state import (
    SecurityPostureStatusEnum, VulnerabilityLifecycleStatusEnum,
    DynamicVulnerabilityEntity, VulnerabilitySeverityEnum
)
from packages.shared_types.src.port_service_state import (
    PortStateEnum, ServiceDaemonStateEnum, TrackedServiceModel
)
from packages.shared_types.src.network_state import ActiveConnectionSessionModel, SessionStateEnum

from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.state_transition_engine import state_transition_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.security_state_engine import security_state_engine

class DuplicateEventError(ValueError):
    pass

class OutOfOrderEventError(ValueError):
    pass

class UnifiedStateCoordinator:
    """Master orchestrator integrating real telemetry and simulation events into the Twin State."""

    def __init__(self):
        # device_id -> DualSourceDeviceState
        self._states: Dict[str, DualSourceDeviceState] = {}
        # Track seen event IDs to prevent duplicate processing
        self._processed_events: set = set()
        # device_id -> latest timestamp seen
        self._latest_timestamps: Dict[str, str] = {}
        # Unified audit history ledger
        self._history: List[StateAuditHistoryEntry] = []

    def _ensure_device_exists(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' does not exist in Device Registry.")

    def _get_or_init(self, device_id: str) -> DualSourceDeviceState:
        self._ensure_device_exists(device_id)
        if device_id not in self._states:
            init_eff = EffectiveTwinStateModel(deviceId=device_id)
            self._states[device_id] = DualSourceDeviceState(
                deviceId=device_id,
                real=SourcePartitionStateModel(),
                simulation=SourcePartitionStateModel(),
                effective=init_eff
            )
        return self._states[device_id]

    def _compute_effective(self, ds: DualSourceDeviceState):
        """Precedence policy: Simulation overrides Real when active; otherwise Real is used."""
        eff = ds.effective
        real = ds.real
        sim = ds.simulation

        # 1. Operational State
        eff.operationalState = sim.operationalState if sim.operationalState is not None else (real.operationalState or "ACTIVE")

        # 2. Performance Metrics
        eff.cpu = sim.cpu if sim.cpu is not None else (real.cpu if real.cpu is not None else 0.0)
        eff.memory = sim.memory if sim.memory is not None else (real.memory if real.memory is not None else 0.0)
        eff.networkUtilisation = sim.networkUtilisation if sim.networkUtilisation is not None else (real.networkUtilisation if real.networkUtilisation is not None else 0.0)

        # Performance Level
        cpu_lvl = performance_state_engine.calculateLevel(eff.cpu)
        mem_lvl = performance_state_engine.calculateLevel(eff.memory)
        eff.performanceLevel = performance_state_engine.calculateCombinedState(cpu_lvl, mem_lvl).value

        # 3. Connections
        eff.activeConnections = sim.activeConnections if sim.activeConnections is not None else (real.activeConnections if real.activeConnections is not None else 0)

        # 4. Open Ports
        eff.openPorts = sorted(list(set(sim.openPorts if sim.openPorts else real.openPorts)))

        # 5. Services
        combined_services = dict(real.services)
        combined_services.update(sim.services)
        eff.services = combined_services

        # 6. Security Posture
        eff.securityStatus = sim.securityStatus if sim.securityStatus is not None else (real.securityStatus or "NORMAL")

        # 7. Vulnerabilities
        combined_vulns = dict(real.vulnerabilities)
        combined_vulns.update(sim.vulnerabilities)
        eff.vulnerabilities = combined_vulns

        eff.lastUpdated = datetime.now(timezone.utc).isoformat()
        ds.timestamp = eff.lastUpdated

    def ingestEvent(self, event: UniversalStateEvent) -> DualSourceDeviceState:
        # 1. Deduplication Check
        if event.eventId in self._processed_events:
            raise DuplicateEventError(f"Duplicate event '{event.eventId}' rejected.")

        self._ensure_device_exists(event.deviceId)

        # 2. Out-of-Order Timestamp Check
        last_ts = self._latest_timestamps.get(event.deviceId)
        if last_ts and event.timestamp < last_ts:
            raise OutOfOrderEventError(f"Out-of-order event for device '{event.deviceId}'. Incoming {event.timestamp} is older than latest {last_ts}.")

        ds = self._get_or_init(event.deviceId)
        target_bucket = ds.real if event.source == StateEventSourceEnum.REAL_NETWORK else ds.simulation
        old_val = getattr(ds.effective, event.metric.value.lower(), None)

        # 3. Metric Dispatcher & Strict Invariant Validation
        m = event.metric
        val = event.value

        if m == SupportedMetricEnum.CPU:
            f_val = float(val)
            if f_val < 0.0 or f_val > 100.0:
                raise ValueError(f"CPU must be between 0.0 and 100.0%. Got {f_val}")
            target_bucket.cpu = round(f_val, 2)
            performance_state_engine.updateCpu(event.deviceId, f_val, source=event.source.value)

        elif m == SupportedMetricEnum.MEMORY:
            f_val = float(val)
            if f_val < 0.0 or f_val > 100.0:
                raise ValueError(f"Memory must be between 0.0 and 100.0%. Got {f_val}")
            target_bucket.memory = round(f_val, 2)
            performance_state_engine.updateMemory(event.deviceId, f_val, source=event.source.value)

        elif m == SupportedMetricEnum.NETWORK_UTILISATION:
            f_val = float(val)
            if f_val < 0.0 or f_val > 100.0:
                raise ValueError(f"Network utilisation must be between 0.0 and 100.0%. Got {f_val}")
            target_bucket.networkUtilisation = round(f_val, 2)
            network_state_engine.updateNetworkMetrics(event.deviceId, f_val)

        elif m == SupportedMetricEnum.CONNECTIONS:
            i_val = int(val)
            if i_val < 0:
                raise ValueError(f"Active connections cannot be negative. Got {i_val}")
            target_bucket.activeConnections = i_val

        elif m == SupportedMetricEnum.OPEN_PORT:
            port_num = int(val.get("port", val) if isinstance(val, dict) else val)
            if port_num < 1 or port_num > 65535:
                raise ValueError(f"Port must be between 1 and 65535. Got {port_num}")
            p_state = str(val.get("state", "OPEN") if isinstance(val, dict) else "OPEN").upper()
            if p_state not in PortStateEnum.__members__:
                raise ValueError(f"Invalid port state: '{p_state}'")

            if p_state == "OPEN":
                if port_num not in target_bucket.openPorts:
                    target_bucket.openPorts.append(port_num)
                port_service_engine.openPort(event.deviceId, port_num, reason=f"Event from {event.source.value}")
            else:
                if port_num in target_bucket.openPorts:
                    target_bucket.openPorts.remove(port_num)
                try:
                    port_service_engine.setPortState(event.deviceId, port_num, PortStateEnum[p_state], reason=f"Event from {event.source.value}")
                except Exception:
                    pass

        elif m == SupportedMetricEnum.SERVICE_STATUS:
            srv_name = str(val.get("name") if isinstance(val, dict) else val)
            srv_status = str(val.get("status", "RUNNING") if isinstance(val, dict) else "RUNNING").upper()
            if srv_status not in ServiceDaemonStateEnum.__members__:
                raise ValueError(f"Invalid service status: '{srv_status}'")
            target_bucket.services[srv_name] = srv_status
            try:
                port_service_engine.setServiceStatus(event.deviceId, srv_name, ServiceDaemonStateEnum[srv_status], reason=f"Event from {event.source.value}")
            except Exception:
                # If service not pre-registered, register dynamically
                port_service_engine.registerService(event.deviceId, TrackedServiceModel(
                    name=srv_name, port=443 if "http" in srv_name.lower() else 8080, status=ServiceDaemonStateEnum[srv_status]
                ))

        elif m == SupportedMetricEnum.SECURITY_STATUS:
            sec_stat = str(val.upper())
            if sec_stat not in SecurityPostureStatusEnum.__members__:
                raise ValueError(f"Invalid security state: '{sec_stat}'")
            target_bucket.securityStatus = sec_stat
            security_state_engine.transitionSecurityStatus(event.deviceId, SecurityPostureStatusEnum[sec_stat], reason=f"Event from {event.source.value}", source=event.source.value)

        elif m == SupportedMetricEnum.VULNERABILITY_STATUS:
            vuln_id = str(val.get("id", "VULN-001") if isinstance(val, dict) else "VULN-001")
            vuln_stat = str(val.get("status", val) if isinstance(val, dict) else val).upper()
            if vuln_stat not in VulnerabilityLifecycleStatusEnum.__members__:
                raise ValueError(f"Invalid vulnerability state: '{vuln_stat}'")
            target_bucket.vulnerabilities[vuln_id] = vuln_stat
            try:
                security_state_engine.transitionVulnerabilityStatus(event.deviceId, vuln_id, VulnerabilityLifecycleStatusEnum[vuln_stat], reason=f"Event from {event.source.value}", source=event.source.value)
            except Exception:
                security_state_engine.addVulnerability(event.deviceId, DynamicVulnerabilityEntity(
                    id=vuln_id, name=f"Dynamic {vuln_id}", severity=VulnerabilitySeverityEnum.HIGH, affectedService="web", status=VulnerabilityLifecycleStatusEnum[vuln_stat]
                ))

        elif m == SupportedMetricEnum.DEVICE_STATE:
            op_stat = str(val.upper())
            if op_stat not in OperationalStatusEnum.__members__:
                raise ValueError(f"Invalid operational state: '{op_stat}'")
            target_bucket.operationalState = op_stat
            state_transition_engine.transitionState(event.deviceId, OperationalStatusEnum[op_stat], reason=f"Event from {event.source.value}", trigger=event.source.value)

        target_bucket.lastUpdated = event.timestamp
        self._compute_effective(ds)

        # 4. Commit Audit History
        new_val = getattr(ds.effective, event.metric.value.lower(), event.value)
        self._history.append(StateAuditHistoryEntry(
            deviceId=event.deviceId,
            metric=event.metric.value,
            oldValue=old_val,
            newValue=new_val,
            source=event.source.value,
            timestamp=event.timestamp
        ))

        self._processed_events.add(event.eventId)
        self._latest_timestamps[event.deviceId] = event.timestamp
        return ds

    def getDeviceDualState(self, device_id: str) -> DualSourceDeviceState:
        return self._get_or_init(device_id)

    def getAuditHistory(self, device_id: Optional[str] = None) -> List[StateAuditHistoryEntry]:
        if device_id:
            self._ensure_device_exists(device_id)
            return [h for h in self._history if h.deviceId == device_id]
        return list(self._history)

    def clear(self):
        self._states.clear()
        self._processed_events.clear()
        self._latest_timestamps.clear()
        self._history.clear()

unified_state_coordinator = UnifiedStateCoordinator()