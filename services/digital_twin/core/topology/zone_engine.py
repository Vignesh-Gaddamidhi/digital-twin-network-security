from typing import Dict, List, Optional, Set
import networkx as nx

from packages.shared_types.src.zone_graph import (
    ZoneDefinitionModel, ZoneBoundaryLinkModel, ZoneSegmentationGraphModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import connection_registry

class ZoneAlreadyExistsError(ValueError):
    pass

class ZoneNotFoundError(KeyError):
    pass

class ZoneEngine:
    """Manages zone definitions, device cluster memberships, and zone-level segmentation graphs."""

    def __init__(self):
        self._zones: Dict[str, ZoneDefinitionModel] = {}
        self._device_to_zone: Dict[str, str] = {}
        self._zone_graph: nx.DiGraph = nx.DiGraph()
        self._init_canonical_zones()

    def _init_canonical_zones(self):
        defaults = [
            ZoneDefinitionModel(id="zone-internet", name="INTERNET", trust_level=0, description="Untrusted external WAN network"),
            ZoneDefinitionModel(id="zone-dmz", name="DMZ", trust_level=2, description="Exposed reverse proxies and public web application tier"),
            ZoneDefinitionModel(id="zone-internal", name="INTERNAL", trust_level=3, description="Internal corporate clients and local core services"),
            ZoneDefinitionModel(id="zone-database", name="DATABASE", trust_level=4, description="Restricted database tier and persistence storage"),
        ]
        for z in defaults:
            self._zones[z.id] = z
            self._zone_graph.add_node(z.id, name=z.name, trust_level=z.trust_level)

    def createZone(self, zone: ZoneDefinitionModel) -> ZoneDefinitionModel:
        if zone.id in self._zones:
            raise ZoneAlreadyExistsError(f"Zone with ID '{zone.id}' already exists.")
        self._zones[zone.id] = zone
        self._zone_graph.add_node(zone.id, name=zone.name, trust_level=zone.trust_level)
        return zone

    def deleteZone(self, zone_id: str) -> bool:
        if zone_id not in self._zones:
            raise ZoneNotFoundError(f"Zone '{zone_id}' not found.")
        
        # Unbind all devices from this zone
        zone = self._zones[zone_id]
        for dev_id in list(zone.devices):
            if dev_id in self._device_to_zone:
                del self._device_to_zone[dev_id]

        if self._zone_graph.has_node(zone_id):
            self._zone_graph.remove_node(zone_id)

        del self._zones[zone_id]
        return True

    def assignDeviceToZone(self, zone_id: str, device_id: str) -> ZoneDefinitionModel:
        if zone_id not in self._zones:
            raise ZoneNotFoundError(f"Zone '{zone_id}' not found.")
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' does not exist in registry.")

        # Remove device from any previous zone
        old_zone_id = self._device_to_zone.get(device_id)
        if old_zone_id and old_zone_id in self._zones:
            if device_id in self._zones[old_zone_id].devices:
                self._zones[old_zone_id].devices.remove(device_id)

        self._zones[zone_id].devices.append(device_id)
        self._device_to_zone[device_id] = zone_id

        # Update metadata on device
        dev.metadata["zone_id"] = zone_id
        dev.metadata["zone_name"] = self._zones[zone_id].name
        device_registry.updateDevice(dev)
        return self._zones[zone_id]

    def removeDeviceFromZone(self, zone_id: str, device_id: str) -> bool:
        if zone_id not in self._zones:
            raise ZoneNotFoundError(f"Zone '{zone_id}' not found.")
        zone = self._zones[zone_id]
        if device_id not in zone.devices:
            return False

        zone.devices.remove(device_id)
        if self._device_to_zone.get(device_id) == zone_id:
            del self._device_to_zone[device_id]
        return True

    def getZone(self, zone_id: str) -> Optional[ZoneDefinitionModel]:
        return self._zones.get(zone_id)

    def listZones(self) -> List[ZoneDefinitionModel]:
        return list(self._zones.values())

    def getZoneDevices(self, zone_id: str) -> List[str]:
        zone = self.getZone(zone_id)
        if not zone:
            raise ZoneNotFoundError(f"Zone '{zone_id}' not found.")
        return list(zone.devices)

    def getDeviceZone(self, device_id: str) -> Optional[str]:
        return self._device_to_zone.get(device_id)

    def getZoneConnections(self, zone_id: str) -> List[ZoneBoundaryLinkModel]:
        """Returns all connections associated with the zone, distinguishing intra-zone from inter-zone."""
        if zone_id not in self._zones:
            raise ZoneNotFoundError(f"Zone '{zone_id}' not found.")

        results = []
        for conn in connection_registry.getAllConnections():
            src_zone = self.getDeviceZone(conn.sourceDevice) or "UNKNOWN"
            dst_zone = self.getDeviceZone(conn.destinationDevice) or "UNKNOWN"

            if src_zone == zone_id or dst_zone == zone_id:
                results.append(ZoneBoundaryLinkModel(
                    connection_id=conn.id,
                    source_device=conn.sourceDevice,
                    destination_device=conn.destinationDevice,
                    source_zone=src_zone,
                    destination_zone=dst_zone,
                    is_inter_zone=(src_zone != dst_zone),
                    protocol=conn.protocol.value if hasattr(conn.protocol, "value") else str(conn.protocol),
                    port=conn.destinationPort
                ))
        return results

    def buildZoneSegmentationGraph(self) -> ZoneSegmentationGraphModel:
        """Condenses the device topology into a macro-level Zone-to-Zone graph."""
        inter_links: List[ZoneBoundaryLinkModel] = []
        adjacency: Dict[str, Set[str]] = {z_id: set() for z_id in self._zones.keys()}

        for conn in connection_registry.getAllConnections():
            src_zone = self.getDeviceZone(conn.sourceDevice)
            dst_zone = self.getDeviceZone(conn.destinationDevice)

            if src_zone and dst_zone and src_zone != dst_zone:
                inter_links.append(ZoneBoundaryLinkModel(
                    connection_id=conn.id,
                    source_device=conn.sourceDevice,
                    destination_device=conn.destinationDevice,
                    source_zone=src_zone,
                    destination_zone=dst_zone,
                    is_inter_zone=True,
                    protocol=conn.protocol.value if hasattr(conn.protocol, "value") else str(conn.protocol),
                    port=conn.destinationPort
                ))
                if src_zone in adjacency:
                    adjacency[src_zone].add(dst_zone)

        return ZoneSegmentationGraphModel(
            zone_count=len(self._zones),
            zones=list(self._zones.values()),
            inter_zone_links=inter_links,
            zone_adjacency={k: sorted(list(v)) for k, v in adjacency.items()}
        )

    def clear(self):
        self._zones.clear()
        self._device_to_zone.clear()
        self._zone_graph.clear()
        self._init_canonical_zones()

zone_engine = ZoneEngine()