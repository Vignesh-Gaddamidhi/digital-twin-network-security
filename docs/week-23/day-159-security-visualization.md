# Day 159: 3D Security State, Risk Shaders, Threat Beacons & Isolation Visualization

## 1. Security State Mapping Architecture
The 3D layer maps canonical security states from `attack_path_graph.nodes` to GPU visual properties without defining duplicate state enums:

| Canonical State | 3D Halo Glow Hex | Emissive Pulse | Mesh Cage Geometry | Link Visibility |
| :--- | :--- | :--- | :--- | :--- |
| **NORMAL** | `#10B981` (Emerald) | Static 0.1x | None | Active / Visible |
| **MONITORED** | `#06B6D4` (Cyan) | Pulsing 1.0x | None | Active / Visible |
| **SUSPICIOUS** | `#F59E0B` (Amber) | Pulsing 1.8x | None | Active / Visible |
| **AT_RISK** | `#F97316` (Orange) | Pulsing 2.5x | Outer Hazard Ring | Active / Monitored |
| **COMPROMISED** | `#EF4444` (Crimson) | Strobe 4.0x | Pulsing Biohazard Aura | Active / Compromised |
| **ISOLATED** | `#64748B` (Slate) | Zero Emissive | Hexagonal Wireframe Cage | Severed / Hidden |
| **UNKNOWN** | `#94A3B8` (Muted) | Static 0.2x | Dotted Perimeter Ring | Indeterminate |

## 2. Risk Level Shaders & Factor Tooltips
Devices display risk tiers computed by Phase 16:
- `LOW`: Subtle green floor projection ring.
- `MEDIUM`: Yellow floor projection ring.
- `HIGH`: Orange elevated projection ring.
- `CRITICAL`: Red pulsating volumetric cylinder.

Tooltips expose the exact multiplicative formula:
$$\text{Risk} = P_{\text{threat}} \times C_{\text{asset}} \times V_{\text{asset}} \times I_{\text{attack}} \times 100$$

## 3. Epistemic Provenance
Every 3D visual badge exposes data origin:
- `REAL_TELEMETRY`: Solid outline badge.
- `SIMULATION`: Dashed yellow badge.
- `PREDICTED`: Dotted cyan badge.