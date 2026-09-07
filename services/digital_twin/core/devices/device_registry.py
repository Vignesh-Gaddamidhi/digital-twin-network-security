from typing import Dict, List, Optional
from services.twin_engine.src.core.twin_state import DeviceEntity

class DeviceRegistry:
    """Manages CRUD operations and identity lookups for twin devices."""

    def __init__(self):
        self._devices: Dict[str, DeviceEntity] = {}

    def create_device(self, device: DeviceEntity) -> DeviceEntity:
        if device.id in self._devices:
            raise ValueError(f"Device with ID {device.id} already exists.")
        self._devices[device.id] = device
        return device

    def get_device(self, device_id: str) -> Optional[DeviceEntity]:
        return self._devices.get(device_id)

    def update_device(self, device: DeviceEntity) -> DeviceEntity:
        if device.id not in self._devices:
            raise KeyError(f"Device {device.id} not registered.")
        self._devices[device.id] = device
        return device

    def delete_device(self, device_id: str) -> bool:
        if device_id in self._devices:
            del self._devices[device_id]
            return True
        return False

    def list_devices(self) -> List[DeviceEntity]:
        return list(self._devices.values())