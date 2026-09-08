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
        # 1. Check local firewall engine zones
        for z in self._zones.values():
            if device_id in z.devices:
                return z.name

        # 2. Check zone_engine if available
        try:
            from services.digital_twin.core.topology.zone_engine import zone_engine
            z_id = zone_engine.getDeviceZone(device_id)
            if z_id:
                clean_name = z_id.replace("zone-", "").upper()
                if clean_name in NetworkZoneTypeEnum.__members__:
                    return NetworkZoneTypeEnum[clean_name]
        except Exception:
            pass

        # 3. Check device model metadata or networkZone attribute
        dev = device_registry.getDevice(device_id)
        if dev:
            raw_zone = dev.metadata.get("zone_name") or dev.metadata.get("zone_id")
            if raw_zone:
                clean = raw_zone.replace("zone-", "").upper()
                if clean in NetworkZoneTypeEnum.__members__:
                    return NetworkZoneTypeEnum[clean]

            if hasattr(dev, "networkZone") and dev.networkZone:
                z_val = dev.networkZone.value if hasattr(dev.networkZone, "value") else str(dev.networkZone)
                z_clean = z_val.upper()
                if z_clean == "EXTERNAL":
                    return NetworkZoneTypeEnum.INTERNET
                if z_clean in NetworkZoneTypeEnum.__members__:
                    return NetworkZoneTypeEnum[z_clean]

        return NetworkZoneTypeEnum.UNKNOWN

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
        return sorted(self._rules.values(), key=lambda r: r.priority)

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

        # Check explicit rules
        for rule in self.listRules():
            if rule.status != "ACTIVE":
                continue

            # Allow EXTERNAL / INTERNET equivalence
            s_match = (rule.sourceZone == src_zone) or (rule.sourceZone == NetworkZoneTypeEnum.INTERNET and src_zone == NetworkZoneTypeEnum.EXTERNAL)
            d_match = (rule.destinationZone == dst_zone) or (rule.destinationZone == NetworkZoneTypeEnum.INTERNET and dst_zone == NetworkZoneTypeEnum.EXTERNAL)

            zone_match = s_match and d_match
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