from typing import Dict, List, Optional
from datetime import datetime, timezone
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

class DeviceAlreadyExistsError(ValueError):
    pass

class DeviceNotFoundError(KeyError):
    pass

class NetworkDeviceRegistry:
    """Production registry managing NetworkDevice entities with strict validation."""

    def __init__(self):
        self._devices: Dict[str, NetworkDeviceModel] = {}

    def createDevice(self, device: NetworkDeviceModel) -> NetworkDeviceModel:
        if device.id in self._devices:
            raise DeviceAlreadyExistsError(f"Device with ID '{device.id}' already exists.")
        
        # Synchronize root lists from interfaces if interfaces provided
        for iface in device.interfaces:
            if iface.ip_address not in device.ipAddresses:
                device.ipAddresses.append(iface.ip_address)
            if iface.mac_address not in device.macAddresses:
                device.macAddresses.append(iface.mac_address)

        device.lastUpdated = datetime.now(timezone.utc).isoformat()
        self._devices[device.id] = device
        return device

    def getDevice(self, device_id: str) -> Optional[NetworkDeviceModel]:
        return self._devices.get(device_id)

    def getAllDevices(self, zone: Optional[NetworkZoneEnum] = None, device_type: Optional[DeviceTypeEnum] = None) -> List[NetworkDeviceModel]:
        results = list(self._devices.values())
        if zone:
            results = [d for d in results if d.networkZone == zone]
        if device_type:
            results = [d for d in results if d.type == device_type]
        return results

    def updateDevice(self, device: NetworkDeviceModel) -> NetworkDeviceModel:
        if device.id not in self._devices:
            raise DeviceNotFoundError(f"Cannot update: Device '{device.id}' not found.")
        
        device.lastUpdated = datetime.now(timezone.utc).isoformat()
        self._devices[device.id] = device
        return device

    def deleteDevice(self, device_id: str) -> bool:
        if device_id not in self._devices:
            raise DeviceNotFoundError(f"Cannot delete: Device '{device_id}' not found.")
        del self._devices[device_id]
        return True

    def count(self) -> int:
        return len(self._devices)

    def clear(self):
        self._devices.clear()

device_registry = NetworkDeviceRegistry()