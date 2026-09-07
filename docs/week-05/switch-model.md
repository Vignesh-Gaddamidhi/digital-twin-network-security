# Day 33: Switch Architecture & Layer 2 Emulation

## 1. Switch Specification
A switch is a Layer 2 multiport bridging device maintaining:
- Physical and virtual switch port definitions (`SwitchPortModel`).
- In-memory CAM table mapping learned MAC addresses to ingress ports (`MacTableEntryModel`).
- VLAN segmentation partitions (`VlanModel`).

## 2. CAM Table Mechanics
- **Dynamic Learning:** Ingress frames record the mapping $(M_{\text{src}}, P_{\text{in}})$ automatically.
- **Aging:** CAM entries expire after 300 seconds of inactivity.
- **Flooding:** Frames with unknown destination MACs flood all active ports in the same VLAN except the ingress port.