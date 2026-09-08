# Phase 5: Switch Model & Layer 2 Bridging
Emulates hardware frame switching:
- Maintains virtual switch ports (`SwitchPortModel`) with status and access/trunk mode.
- Simulates Content-Addressable Memory (CAM) tables with dynamic source MAC learning and aging.
- Implements broadcast flooding for unknown unicast/broadcast MACs (`FF:FF:FF:FF:FF:FF`) and isolates traffic across VLAN domains.