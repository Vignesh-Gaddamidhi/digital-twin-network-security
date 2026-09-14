# Day 143: Live Network Topology & Visual Security Canvas

## 1. Network Zone Layout Grid
The topology canvas groups digital twin devices into designated security perimeter boundaries:
- `INTERNET`: External adversary source nodes (`ATTACKER-EXT`).
- `DMZ`: Public-facing application daemons (`WEB-01`).
- `INTERNAL`: Corporate user LAN workstations and local infrastructure (`CLIENT-01`, `DNS-SERVER-01`).
- `DATABASE`: Mission-critical segmented data tier (`DB-01`).
- `MANAGEMENT`: Out-of-band monitoring and orchestration.

## 2. Multi-Modal Node Status Design
To ensure accessibility and operational clarity:
- **Icons & Shapes:** Distinguishes firewalls (shield), databases (cylinder), servers (rack), and workstations (desktop).
- **Security Badge:** Explicitly displays state (`NORMAL`, `AT_RISK`, `COMPROMISED`, `ISOLATED`).
- **Tactical Rings:** Renders risk color rings (`LOW` = Green, `MEDIUM` = Amber, `HIGH` = Orange, `CRITICAL` = Red).

## 3. Real-Time Event Synchronization
When a security control is triggered (e.g. host isolation), the canvas reactively severs incident links and updates node states without full-page reloads.