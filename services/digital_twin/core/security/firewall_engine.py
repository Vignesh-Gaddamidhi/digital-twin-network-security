from typing import Dict, List, Optional
from packages.shared_types.src.firewall import (
    FirewallRuleModel, NetworkZoneModel, NetworkZoneTypeEnum, 
    FirewallActionEnum, TrafficInspectionResult
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class FirewallEngine:
    """Manages network zone segregation and evaluates inter-zone firewall policies."""

    def __init__(self):
        self._zones: Dict[str, NetworkZoneModel] = {}
        self._rules: Dict[str, FirewallRuleModel] = {}
        self._init_default_zones()

    def _init_default_zones(self):
        defaults = [
            NetworkZoneModel(id="zone-internet", name=NetworkZoneTypeEnum.INTERNET, trustLevel=0),
            NetworkZoneModel(id="zone-dmz", name=NetworkZoneTypeEnum.DMZ, trustLevel=2),
            NetworkZoneModel(id="zone-internal", name=NetworkZoneTypeEnum.INTERNAL, trustLevel=3),
            NetworkZoneModel(id="zone-database", name=NetworkZoneTypeEnum.DATABASE, trustLevel=4),
            NetworkZoneModel(id="zone-mgmt", name=NetworkZoneTypeEnum.MANAGEMENT, trustLevel=5),
        ]
        for z in defaults:
            self._zones[z.id] = z

    # --- Zone Management ---
    def createZone(self, zone: NetworkZoneModel) -> NetworkZoneModel:
        if zone.id in self._zones:
            raise ValueError(f"Zone '{zone.id}' already exists.")
        self._zones[zone.id] = zone
        return zone

    def getZone(self, zone_id: str) -> Optional[NetworkZoneModel]:
        return self._zones.get(zone_id)

    def listZones(self) -> List[NetworkZoneModel]:
        return list(self._zones.values())

    def assignDeviceToZone(self, zone_id: str, device_id: str) -> NetworkZoneModel:
        zone = self.getZone(zone_id)
        if not zone:
            raise ValueError(f"Zone '{zone_id}' not found.")
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found in registry.")

        # Remove from any existing zones
        for z in self._zones.values():
            if device_id in z.devices:
                z.devices.remove(device_id)

        zone.devices.append(device_id)
        dev.metadata["zone_id"] = zone_id
        device_registry.updateDevice(dev)
        return zone

    def removeDeviceFromZone(self, zone_id: str, device_id: str) -> bool:
        zone = self.getZone(zone_id)
        if not zone or device_id not in zone.devices:
            return False
        zone.devices.remove(device_id)
        return True

    def getDeviceZone(self, device_id: str) -> NetworkZoneTypeEnum:
        for z in self._zones.values():
            if device_id in z.devices:
                return z.name
        dev = device_registry.getDevice(device_id)
        if dev and hasattr(dev, "networkZone") and dev.networkZone:
            try:
                return NetworkZoneTypeEnum(dev.networkZone.value)
            except Exception:
                pass
        return NetworkZoneTypeEnum.UNKNOWN

    # --- Firewall Policy Rule Management ---
    def addRule(self, rule: FirewallRuleModel) -> FirewallRuleModel:
        if rule.id in self._rules:
            raise ValueError(f"Rule with ID '{rule.id}' already exists.")
        self._rules[rule.id] = rule
        return rule

    def removeRule(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def listRules(self) -> List[FirewallRuleModel]:
        # Evaluated strictly by ascending priority number
        return sorted(self._rules.values(), key=lambda r: r.priority)

    # --- Stateful Policy Inspection ---
    def inspectTraffic(
        self,
        source_device_id: str,
        destination_device_id: str,
        protocol: str,
        destination_port: Optional[int]
    ) -> TrafficInspectionResult:
        src_zone = self.getDeviceZone(source_device_id)
        dst_zone = self.getDeviceZone(destination_device_id)

        # Intra-zone traffic within trusted networks is permitted by default
        if src_zone == dst_zone and src_zone in (NetworkZoneTypeEnum.INTERNAL, NetworkZoneTypeEnum.DATABASE):
            return TrafficInspectionResult(
                source_device_id=source_device_id,
                destination_device_id=destination_device_id,
                source_zone=src_zone,
                destination_zone=dst_zone,
                protocol=protocol,
                destination_port=destination_port,
                decision=FirewallActionEnum.ALLOW,
                matched_rule_id="INTRA_ZONE_DEFAULT",
                explanation=f"Traffic within trusted zone {src_zone.value} permitted by default."
            )

        # Check explicit rules in priority order
        for rule in self.listRules():
            if rule.status != "ACTIVE":
                continue

            zone_match = (rule.sourceZone == src_zone and rule.destinationZone == dst_zone)
            proto_match = (rule.protocol.upper() in ("ANY", protocol.upper()))
            port_match = (rule.destinationPort is None or rule.destinationPort == destination_port)

            if zone_match and proto_match and port_match:
                return TrafficInspectionResult(
                    source_device_id=source_device_id,
                    destination_device_id=destination_device_id,
                    source_zone=src_zone,
                    destination_zone=dst_zone,
                    protocol=protocol,
                    destination_port=destination_port,
                    decision=rule.action,
                    matched_rule_id=rule.id,
                    explanation=f"Traffic matched policy rule '{rule.id}' ({rule.description}) -> {rule.action.value}."
                )

        # Implicit Default Deny
        return TrafficInspectionResult(
            source_device_id=source_device_id,
            destination_device_id=destination_device_id,
            source_zone=src_zone,
            destination_zone=dst_zone,
            protocol=protocol,
            destination_port=destination_port,
            decision=FirewallActionEnum.DENY,
            matched_rule_id="DEFAULT_IMPLICIT_DENY",
            explanation=f"No matching rule from {src_zone.value} to {dst_zone.value} for {protocol}:{destination_port}. Implicit DENY enforced."
        )

    def clear(self):
        self._rules.clear()
        self._zones.clear()
        self._init_default_zones()

firewall_engine = FirewallEngine()