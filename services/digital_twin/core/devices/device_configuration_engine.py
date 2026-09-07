from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import ipaddress
import copy

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, NetworkInterfaceConfig, RouteEntryConfig, 
    NetworkZoneEnum, ConfigurationHistoryRecord
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class DeviceConfigurationEngine:
    """Manages dynamic reconfiguration of twin devices and maintains an immutable audit ledger."""

    def __init__(self):
        self._history: List[ConfigurationHistoryRecord] = []

    def _record_mutation(self, device_id: str, action: str, field: str, prev: Any, new: Any, operator: str, reason: str):
        record = ConfigurationHistoryRecord(
            device_id=device_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            field_changed=field,
            previous_value=copy.deepcopy(prev),
            new_value=copy.deepcopy(new),
            operator=operator,
            reason=reason
        )
        self._history.append(record)
        return record

    def configureInterface(self, device_id: str, iface_config: NetworkInterfaceConfig, operator: str = "ADMIN", reason: str = "Interface update") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        prev_interfaces = [i.model_dump() for i in device.interfaces]
        existing_idx = next((idx for idx, i in enumerate(device.interfaces) if i.interface_id == iface_config.interface_id), None)

        if existing_idx is not None:
            device.interfaces[existing_idx] = iface_config
        else:
            device.interfaces.append(iface_config)

        # Sync root lists
        if iface_config.ip_address not in device.ipAddresses and iface_config.ip_address != "0.0.0.0":
            device.ipAddresses.append(iface_config.ip_address)
        if iface_config.mac_address not in device.macAddresses:
            device.macAddresses.append(iface_config.mac_address)

        self._record_mutation(device_id, "CONFIGURE_INTERFACE", f"interfaces.{iface_config.interface_id}", prev_interfaces, [i.model_dump() for i in device.interfaces], operator, reason)
        return device_registry.updateDevice(device)

    def assignIPAddress(self, device_id: str, ip_address: str, interface_id: str = "eth0", operator: str = "ADMIN", reason: str = "Assign IP") -> NetworkDeviceModel:
        # Validate format
        ipaddress.ip_address(ip_address)

        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        prev_ips = list(device.ipAddresses)
        if ip_address not in device.ipAddresses:
            device.ipAddresses.append(ip_address)

        # Update interface if exists
        target_iface = next((i for i in device.interfaces if i.interface_id == interface_id), None)
        if target_iface:
            target_iface.ip_address = ip_address
        else:
            # Create default interface
            device.interfaces.append(NetworkInterfaceConfig(
                interface_id=interface_id,
                ip_address=ip_address,
                mac_address="00:50:56:FE:00:01"
            ))

        self._record_mutation(device_id, "ASSIGN_IP", "ipAddresses", prev_ips, device.ipAddresses, operator, reason)
        return device_registry.updateDevice(device)

    def removeIPAddress(self, device_id: str, ip_address: str, operator: str = "ADMIN", reason: str = "Revoke IP") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        if ip_address not in device.ipAddresses:
            raise ValueError(f"IP address '{ip_address}' is not assigned to device '{device_id}'.")

        prev_ips = list(device.ipAddresses)
        device.ipAddresses.remove(ip_address)

        # Clear from interface
        for iface in device.interfaces:
            if iface.ip_address == ip_address:
                iface.ip_address = "0.0.0.0"

        self._record_mutation(device_id, "REMOVE_IP", "ipAddresses", prev_ips, device.ipAddresses, operator, reason)
        return device_registry.updateDevice(device)

    def addService(self, device_id: str, service_name: str, operator: str = "ADMIN", reason: str = "Deploy service") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        prev_services = list(device.services)
        if service_name not in device.services:
            device.services.append(service_name)

        self._record_mutation(device_id, "ADD_SERVICE", "services", prev_services, device.services, operator, reason)
        return device_registry.updateDevice(device)

    def removeService(self, device_id: str, service_name: str, operator: str = "ADMIN", reason: str = "Stop service") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        if service_name not in device.services:
            raise ValueError(f"Service '{service_name}' not running on device '{device_id}'.")

        prev_services = list(device.services)
        device.services.remove(service_name)

        self._record_mutation(device_id, "REMOVE_SERVICE", "services", prev_services, device.services, operator, reason)
        return device_registry.updateDevice(device)

    def openPort(self, device_id: str, port_number: int, operator: str = "ADMIN", reason: str = "Open port listener") -> NetworkDeviceModel:
        if not (1 <= port_number <= 65535):
            raise ValueError(f"Port number {port_number} out of valid range (1-65535).")

        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        prev_ports = list(device.ports)
        if port_number not in device.ports:
            device.ports.append(port_number)
            device.ports.sort()

        self._record_mutation(device_id, "OPEN_PORT", "ports", prev_ports, device.ports, operator, reason)
        return device_registry.updateDevice(device)

    def closePort(self, device_id: str, port_number: int, operator: str = "ADMIN", reason: str = "Close port listener") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        if port_number not in device.ports:
            raise ValueError(f"Port {port_number} is not open on device '{device_id}'.")

        prev_ports = list(device.ports)
        device.ports.remove(port_number)

        self._record_mutation(device_id, "CLOSE_PORT", "ports", prev_ports, device.ports, operator, reason)
        return device_registry.updateDevice(device)

    def changeZone(self, device_id: str, new_zone: NetworkZoneEnum, operator: str = "ADMIN", reason: str = "Zone relocation") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        prev_zone = device.networkZone.value
        device.networkZone = new_zone

        self._record_mutation(device_id, "CHANGE_ZONE", "networkZone", prev_zone, new_zone.value, operator, reason)
        return device_registry.updateDevice(device)

    def addRoute(self, device_id: str, route: RouteEntryConfig, operator: str = "ADMIN", reason: str = "Route injection") -> NetworkDeviceModel:
        device = device_registry.getDevice(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")

        prev_routes = [r.model_dump() for r in device.routes]
        # Overwrite route if same destination prefix exists
        device.routes = [r for r in device.routes if r.destination_cidr != route.destination_cidr]
        device.routes.append(route)

        self._record_mutation(device_id, "ADD_ROUTE", "routes", prev_routes, [r.model_dump() for r in device.routes], operator, reason)
        return device_registry.updateDevice(device)

    def getConfigurationHistory(self, device_id: Optional[str] = None) -> List[ConfigurationHistoryRecord]:
        if device_id:
            return [h for h in self._history if h.device_id == device_id]
        return list(self._history)

    def clearHistory(self):
        self._history.clear()

config_engine = DeviceConfigurationEngine()