from typing import Dict, List, Optional, Set
from datetime import datetime, timezone

from packages.shared_types.src.switch import (
    SwitchPortModel, MacTableEntryModel, VlanModel, 
    PortStatusEnum, PortModeEnum, Layer2FrameForwardResult
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class SwitchDeviceState:
    def __init__(self, switch_id: str, port_count: int = 24):
        self.switch_id = switch_id
        self.ports: Dict[int, SwitchPortModel] = {
            p: SwitchPortModel(port_number=p, status=PortStatusEnum.UP, vlan_id=1)
            for p in range(1, port_count + 1)
        }
        self.mac_table: Dict[str, MacTableEntryModel] = {}
        self.vlans: Dict[int, VlanModel] = {
            1: VlanModel(vlan_id=1, name="Default", member_ports=list(self.ports.keys()))
        }

class SwitchEngine:
    """Simulates Layer 2 switching logic, MAC address learning, and frame forwarding."""

    def __init__(self):
        self._switches: Dict[str, SwitchDeviceState] = {}

    def _get_or_init_switch(self, switch_id: str) -> SwitchDeviceState:
        dev = device_registry.getDevice(switch_id)
        if not dev:
            raise DeviceNotFoundError(f"Switch '{switch_id}' not found in Device Registry.")
        if switch_id not in self._switches:
            self._switches[switch_id] = SwitchDeviceState(switch_id)
        return self._switches[switch_id]

    def connectDeviceToSwitch(self, switch_id: str, port_number: int, device_id: str, mac_address: str) -> SwitchPortModel:
        state = self._get_or_init_switch(switch_id)
        if port_number not in state.ports:
            raise ValueError(f"Port {port_number} does not exist on switch '{switch_id}'.")

        target_dev = device_registry.getDevice(device_id)
        if not target_dev:
            raise DeviceNotFoundError(f"Device '{device_id}' does not exist.")

        port = state.ports[port_number]
        port.connected_device_id = device_id
        port.connected_mac = mac_address.upper()
        port.status = PortStatusEnum.UP

        # Auto-learn MAC into CAM table
        self.learnMacAddress(switch_id, mac_address, port_number, port.vlan_id)

        # Update VLAN membership list
        vlan = state.vlans.get(port.vlan_id)
        if vlan and device_id not in vlan.member_devices:
            vlan.member_devices.append(device_id)

        return port

    def disconnectDeviceFromSwitch(self, switch_id: str, port_number: int) -> SwitchPortModel:
        state = self._get_or_init_switch(switch_id)
        if port_number not in state.ports:
            raise ValueError(f"Port {port_number} not found.")

        port = state.ports[port_number]
        old_mac = port.connected_mac
        old_dev = port.connected_device_id

        port.connected_device_id = None
        port.connected_mac = None

        if old_mac and old_mac in state.mac_table:
            del state.mac_table[old_mac]

        if old_dev:
            vlan = state.vlans.get(port.vlan_id)
            if vlan and old_dev in vlan.member_devices:
                vlan.member_devices.remove(old_dev)

        return port

    def changePortState(self, switch_id: str, port_number: int, status: PortStatusEnum) -> SwitchPortModel:
        state = self._get_or_init_switch(switch_id)
        if port_number not in state.ports:
            raise ValueError(f"Port {port_number} not found.")

        port = state.ports[port_number]
        port.status = status
        return port

    def learnMacAddress(self, switch_id: str, mac_address: str, port_number: int, vlan_id: int = 1) -> MacTableEntryModel:
        state = self._get_or_init_switch(switch_id)
        mac_clean = mac_address.upper()
        entry = MacTableEntryModel(
            mac_address=mac_clean,
            port_number=port_number,
            vlan_id=vlan_id,
            last_seen=datetime.now(timezone.utc).isoformat()
        )
        state.mac_table[mac_clean] = entry
        return entry

    def lookupMacAddress(self, switch_id: str, mac_address: str) -> Optional[MacTableEntryModel]:
        state = self._get_or_init_switch(switch_id)
        return state.mac_table.get(mac_address.upper())

    def getMacTable(self, switch_id: str) -> List[MacTableEntryModel]:
        state = self._get_or_init_switch(switch_id)
        return list(state.mac_table.values())

    def createVlan(self, switch_id: str, vlan_id: int, name: str, subnet: Optional[str] = None) -> VlanModel:
        state = self._get_or_init_switch(switch_id)
        if vlan_id in state.vlans:
            raise ValueError(f"VLAN {vlan_id} already exists on switch '{switch_id}'.")

        vlan = VlanModel(vlan_id=vlan_id, name=name, subnet=subnet)
        state.vlans[vlan_id] = vlan
        return vlan

    def assignPortToVlan(self, switch_id: str, port_number: int, vlan_id: int) -> SwitchPortModel:
        state = self._get_or_init_switch(switch_id)
        if port_number not in state.ports:
            raise ValueError(f"Port {port_number} not found.")
        if vlan_id not in state.vlans:
            raise ValueError(f"VLAN {vlan_id} does not exist.")

        port = state.ports[port_number]
        old_vlan = state.vlans.get(port.vlan_id)
        if old_vlan and port_number in old_vlan.member_ports:
            old_vlan.member_ports.remove(port_number)

        port.vlan_id = vlan_id
        state.vlans[vlan_id].member_ports.append(port_number)

        # Update connected device in VLAN list
        if port.connected_device_id:
            if old_vlan and port.connected_device_id in old_vlan.member_devices:
                old_vlan.member_devices.remove(port.connected_device_id)
            if port.connected_device_id not in state.vlans[vlan_id].member_devices:
                state.vlans[vlan_id].member_devices.append(port.connected_device_id)

        # Update CAM table entry VLAN if mapped
        if port.connected_mac and port.connected_mac in state.mac_table:
            state.mac_table[port.connected_mac].vlan_id = vlan_id

        return port

    def processEthernetFrame(self, switch_id: str, ingress_port: int, source_mac: str, destination_mac: str) -> Layer2FrameForwardResult:
        """Simulates Layer 2 switching: dynamic learning and unicast forwarding / flooding."""
        state = self._get_or_init_switch(switch_id)
        if ingress_port not in state.ports:
            raise ValueError(f"Ingress port {ingress_port} does not exist.")

        in_port = state.ports[ingress_port]
        if in_port.status != PortStatusEnum.UP:
            return Layer2FrameForwardResult(
                source_mac=source_mac,
                destination_mac=destination_mac,
                vlan_id=in_port.vlan_id,
                ingress_port=ingress_port,
                forwarding_action="DROP",
                egress_ports=[],
                explanation=f"Ingress port {ingress_port} is DOWN/BLOCKED."
            )

        vlan_id = in_port.vlan_id

        # 1. Dynamic Source Learning
        self.learnMacAddress(switch_id, source_mac, ingress_port, vlan_id)

        # 2. Destination Lookup
        dest_clean = destination_mac.upper()
        cam_entry = state.mac_table.get(dest_clean)

        # Broadcast address check
        if dest_clean in ("FF:FF:FF:FF:FF:FF", "BROADCAST"):
            flood_ports = [
                p_num for p_num, p in state.ports.items()
                if p_num != ingress_port and p.status == PortStatusEnum.UP and (p.vlan_id == vlan_id or p.mode == PortModeEnum.TRUNK)
            ]
            return Layer2FrameForwardResult(
                source_mac=source_mac,
                destination_mac=destination_mac,
                vlan_id=vlan_id,
                ingress_port=ingress_port,
                forwarding_action="FLOOD",
                egress_ports=flood_ports,
                explanation=f"Broadcast frame flooded out {len(flood_ports)} ports in VLAN {vlan_id}."
            )

        # Unicast Match within same VLAN
        if cam_entry and cam_entry.vlan_id == vlan_id:
            out_port_num = cam_entry.port_number
            out_port = state.ports[out_port_num]

            if out_port_num == ingress_port:
                return Layer2FrameForwardResult(
                    source_mac=source_mac,
                    destination_mac=destination_mac,
                    vlan_id=vlan_id,
                    ingress_port=ingress_port,
                    forwarding_action="DROP",
                    egress_ports=[],
                    explanation="Destination MAC is on the same ingress segment."
                )

            if out_port.status == PortStatusEnum.UP:
                return Layer2FrameForwardResult(
                    source_mac=source_mac,
                    destination_mac=destination_mac,
                    vlan_id=vlan_id,
                    ingress_port=ingress_port,
                    forwarding_action="FORWARD_UNICAST",
                    egress_ports=[out_port_num],
                    explanation=f"Known unicast forwarded to port {out_port_num} via CAM table."
                )

        # Unknown Unicast -> Flood within VLAN
        flood_ports = [
            p_num for p_num, p in state.ports.items()
            if p_num != ingress_port and p.status == PortStatusEnum.UP and (p.vlan_id == vlan_id or p.mode == PortModeEnum.TRUNK)
        ]
        return Layer2FrameForwardResult(
            source_mac=source_mac,
            destination_mac=destination_mac,
            vlan_id=vlan_id,
            ingress_port=ingress_port,
            forwarding_action="FLOOD",
            egress_ports=flood_ports,
            explanation=f"Unknown unicast flooded to {len(flood_ports)} ports in VLAN {vlan_id}."
        )

switch_engine = SwitchEngine()