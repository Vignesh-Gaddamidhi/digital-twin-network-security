from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from services.digital_twin.core.devices.network_device_registry import device_registry

class UnknownDeviceEntity(BaseModel):
    ipAddress: str
    firstSeen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastSeen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    observedPorts: List[int] = Field(default_factory=list)
    observedProtocols: List[str] = Field(default_factory=list)
    eventCount: int = 1

class TwinDeviceResolver:
    """Resolves IP addresses to Digital Twin device IDs with unmanaged asset tracking."""

    def __init__(self):
        self.unknown_devices: Dict[str, UnknownDeviceEntity] = {}

    def resolve(self, ip: str, port: Optional[int] = None, protocol: Optional[str] = None) -> str:
        if not ip or ip == "0.0.0.0":
            return "UNKNOWN_DEVICE"

        # 1. Query device registry directly
        devices = []
        if hasattr(device_registry, "getAllDevices"):
            devices = device_registry.getAllDevices()
        elif hasattr(device_registry, "listDevices"):
            devices = device_registry.listDevices()
        elif hasattr(device_registry, "_devices"):
            devices = list(device_registry._devices.values())

        for dev in devices:
            if getattr(dev, "ipAddress", None) == ip:
                return dev.id
            if dev.id.lower() in ip.lower() or getattr(dev, "hostname", "").lower() in ip.lower():
                return dev.id

        # 2. Canonical testbed subnets (strictly bound to internal 192.168.1.x / 10.0.0.x testbed subnets)
        if ip.startswith("192.168.1.") or ip.startswith("10.0.0."):
            if ip.endswith(".10") or "client" in ip.lower():
                return "CLIENT-01"
            if ip.endswith(".20") or "web" in ip.lower():
                return "WEB-01"
            if ip.endswith(".22") or "server" in ip.lower():
                return "SERVER-01"
            if ip.endswith(".53") or "dns" in ip.lower():
                return "DNS-01"
            if ip.endswith(".100") or "db" in ip.lower():
                return "DB-01"

        # 3. Unmapped asset tracking
        self._record_unknown_device(ip, port, protocol)
        return "UNKNOWN_DEVICE"

    def _record_unknown_device(self, ip: str, port: Optional[int], protocol: Optional[str]):
        now = datetime.now(timezone.utc).isoformat()
        if ip not in self.unknown_devices:
            self.unknown_devices[ip] = UnknownDeviceEntity(
                ipAddress=ip,
                firstSeen=now,
                lastSeen=now,
                observedPorts=[port] if port else [],
                observedProtocols=[protocol] if protocol else []
            )
        else:
            entity = self.unknown_devices[ip]
            entity.lastSeen = now
            entity.eventCount += 1
            if port and port not in entity.observedPorts:
                entity.observedPorts.append(port)
            if protocol and protocol not in entity.observedProtocols:
                entity.observedProtocols.append(protocol)

    def clear(self):
        self.unknown_devices.clear()

twin_device_resolver = TwinDeviceResolver()