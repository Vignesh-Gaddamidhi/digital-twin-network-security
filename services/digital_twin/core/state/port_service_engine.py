from typing import Dict, List, Optional
from datetime import datetime, timezone

from packages.shared_types.src.port_service_state import (
    PortStateEnum, ServiceDaemonStateEnum, TrackedPortModel,
    TrackedServiceModel, DevicePortServiceSnapshotModel, PortServiceAuditEvent
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class PortNotFoundError(KeyError):
    pass

class ServiceNotFoundError(KeyError):
    pass

class DuplicateServiceError(ValueError):
    pass

class PortServiceEngine:
    """Manages active Layer 4 ports, Layer 7 service daemons, and their dynamic lifecycles."""

    def __init__(self):
        # device_id -> { port_number: TrackedPortModel }
        self._device_ports: Dict[str, Dict[int, TrackedPortModel]] = {}
        # device_id -> { service_name: TrackedServiceModel }
        self._device_services: Dict[str, Dict[str, TrackedServiceModel]] = {}
        # Audit history ledger
        self._audit_events: List[PortServiceAuditEvent] = []

    def _ensure_device_exists(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found in Device Registry.")

    def _sync_to_device_registry(self, device_id: str):
        """Synchronizes open ports and running services to the root DeviceRegistry."""
        dev = device_registry.getDevice(device_id)
        if not dev:
            return

        ports_dict = self._device_ports.get(device_id, {})
        open_ports = [p.port for p in ports_dict.values() if p.state == PortStateEnum.OPEN]
        dev.ports = sorted(list(set(open_ports)))

        services_dict = self._device_services.get(device_id, {})
        running_services = [s.name for s in services_dict.values() if s.status == ServiceDaemonStateEnum.RUNNING]
        dev.services = sorted(list(set(running_services)))

        device_registry.updateDevice(dev)

    def _record_audit(self, device_id: str, event_type: str, target: str, prev: Optional[str], new_val: str, reason: str):
        record = PortServiceAuditEvent(
            deviceId=device_id,
            eventType=event_type,
            target=str(target),
            previousState=prev,
            newState=new_val,
            timestamp=datetime.now(timezone.utc).isoformat(),
            reason=reason
        )
        self._audit_events.append(record)

    # --- 1. PORT MANAGEMENT ---
    def openPort(self, device_id: str, port_number: int, protocol: str = "TCP", service_name: str = "unknown", reason: str = "Open port requested") -> TrackedPortModel:
        self._ensure_device_exists(device_id)
        if device_id not in self._device_ports:
            self._device_ports[device_id] = {}

        now_ts = datetime.now(timezone.utc).isoformat()
        prev = self._device_ports[device_id].get(port_number)
        prev_state = prev.state.value if prev else None

        port_model = TrackedPortModel(
            port=port_number,
            protocol=protocol,
            service=service_name,
            state=PortStateEnum.OPEN,
            lastUpdated=now_ts
        )
        self._device_ports[device_id][port_number] = port_model
        self._sync_to_device_registry(device_id)

        self._record_audit(device_id, "PORT_OPENED", str(port_number), prev_state, PortStateEnum.OPEN.value, reason)
        return port_model

    def closePort(self, device_id: str, port_number: int, reason: str = "Close port requested") -> TrackedPortModel:
        self._ensure_device_exists(device_id)
        ports_dict = self._device_ports.get(device_id, {})
        if port_number not in ports_dict:
            raise PortNotFoundError(f"Port {port_number} not configured on device '{device_id}'.")

        prev = ports_dict[port_number]
        prev_state = prev.state.value
        prev.state = PortStateEnum.CLOSED
        prev.lastUpdated = datetime.now(timezone.utc).isoformat()

        self._sync_to_device_registry(device_id)
        self._record_audit(device_id, "PORT_CLOSED", str(port_number), prev_state, PortStateEnum.CLOSED.value, reason)
        return prev

    def setPortState(self, device_id: str, port_number: int, state: PortStateEnum, reason: str = "Port state update") -> TrackedPortModel:
        self._ensure_device_exists(device_id)
        ports_dict = self._device_ports.get(device_id, {})
        if port_number not in ports_dict:
            raise PortNotFoundError(f"Port {port_number} not found on device '{device_id}'.")

        prev = ports_dict[port_number]
        prev_state = prev.state.value
        prev.state = state
        prev.lastUpdated = datetime.now(timezone.utc).isoformat()

        self._sync_to_device_registry(device_id)
        self._record_audit(device_id, "PORT_STATE_CHANGED", str(port_number), prev_state, state.value, reason)
        return prev

    def getPort(self, device_id: str, port_number: int) -> TrackedPortModel:
        self._ensure_device_exists(device_id)
        ports_dict = self._device_ports.get(device_id, {})
        if port_number not in ports_dict:
            raise PortNotFoundError(f"Port {port_number} not configured on device '{device_id}'.")
        return ports_dict[port_number]

    def listPorts(self, device_id: str) -> List[TrackedPortModel]:
        self._ensure_device_exists(device_id)
        return list(self._device_ports.get(device_id, {}).values())

    # --- 2. SERVICE MANAGEMENT ---
    def registerService(self, device_id: str, service: TrackedServiceModel, reason: str = "Service registered") -> TrackedServiceModel:
        self._ensure_device_exists(device_id)
        if device_id not in self._device_services:
            self._device_services[device_id] = {}

        if service.name in self._device_services[device_id]:
            raise DuplicateServiceError(f"Service '{service.name}' already registered on device '{device_id}'.")

        self._device_services[device_id][service.name] = service

        # Auto-open or bind corresponding port
        self.openPort(device_id, service.port, protocol=service.protocol, service_name=service.name, reason=f"Port bound to service '{service.name}'")
        self._sync_to_device_registry(device_id)

        self._record_audit(device_id, "SERVICE_STARTED", service.name, None, service.status.value, reason)
        return service

    def setServiceStatus(self, device_id: str, service_name: str, status: ServiceDaemonStateEnum, reason: str = "Status update") -> TrackedServiceModel:
        self._ensure_device_exists(device_id)
        srv_dict = self._device_services.get(device_id, {})
        if service_name not in srv_dict:
            raise ServiceNotFoundError(f"Service '{service_name}' not found on device '{device_id}'.")

        srv = srv_dict[service_name]
        prev_status = srv.status.value
        srv.status = status
        srv.lastUpdated = datetime.now(timezone.utc).isoformat()

        # Cascade failure/stop to port state
        ports_dict = self._device_ports.get(device_id, {})
        if srv.port in ports_dict:
            port_obj = ports_dict[srv.port]
            if status in (ServiceDaemonStateEnum.STOPPED, ServiceDaemonStateEnum.FAILED):
                port_obj.state = PortStateEnum.CLOSED
            elif status == ServiceDaemonStateEnum.RUNNING:
                port_obj.state = PortStateEnum.OPEN

        self._sync_to_device_registry(device_id)

        event_type = f"SERVICE_{status.value}"
        self._record_audit(device_id, event_type, service_name, prev_status, status.value, reason)
        return srv

    def startService(self, device_id: str, service_name: str, reason: str = "Service started") -> TrackedServiceModel:
        return self.setServiceStatus(device_id, service_name, ServiceDaemonStateEnum.RUNNING, reason=reason)

    def stopService(self, device_id: str, service_name: str, reason: str = "Service stopped") -> TrackedServiceModel:
        return self.setServiceStatus(device_id, service_name, ServiceDaemonStateEnum.STOPPED, reason=reason)

    def failService(self, device_id: str, service_name: str, reason: str = "Process crash/failure") -> TrackedServiceModel:
        return self.setServiceStatus(device_id, service_name, ServiceDaemonStateEnum.FAILED, reason=reason)

    def getService(self, device_id: str, service_name: str) -> TrackedServiceModel:
        self._ensure_device_exists(device_id)
        srv_dict = self._device_services.get(device_id, {})
        if service_name not in srv_dict:
            raise ServiceNotFoundError(f"Service '{service_name}' not found on device '{device_id}'.")
        return srv_dict[service_name]

    def listServices(self, device_id: str) -> List[TrackedServiceModel]:
        self._ensure_device_exists(device_id)
        return list(self._device_services.get(device_id, {}).values())

    # --- 3. SNAPSHOT & AUDIT ---
    def getDeviceSnapshot(self, device_id: str) -> DevicePortServiceSnapshotModel:
        self._ensure_device_exists(device_id)
        return DevicePortServiceSnapshotModel(
            deviceId=device_id,
            ports=self.listPorts(device_id),
            services=self.listServices(device_id)
        )

    def getAuditEvents(self, device_id: Optional[str] = None) -> List[PortServiceAuditEvent]:
        if device_id:
            self._ensure_device_exists(device_id)
            return [e for e in self._audit_events if e.deviceId == device_id]
        return list(self._audit_events)

    def clear(self):
        self._device_ports.clear()
        self._device_services.clear()
        self._audit_events.clear()

port_service_engine = PortServiceEngine()