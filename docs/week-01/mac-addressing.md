# Day 2: MAC Addressing & Layer-2 Switching Dynamics

## 1. Structure
- 48-bit hexadecimal format: `XX:XX:XX:XX:XX:XX`.
- **First 24 bits (OUI):** Organizationally Unique Identifier (Manufacturer assignment).
- **Last 24 bits (NIC Serial):** Unique host serial sequence.

## 2. Switching Logic & CAM Table
Switches maintain a Content Addressable Memory (CAM) table mapping MAC addresses to physical switch ports.