# Day 158: 3D Network Links, Topology Curves & Traffic Particle Visualization

## 1. Network Link Geometry & Splines
Each connection edge defined in the Digital Twin graph (`attack_path_graph.edges`) maps to a 3D parametric curve:
- **Linear / Catmull-Rom Spline**: Evaluates points between source node $(x_1, y_1, z_1)$ and target $(x_2, y_2, z_2)$.
- **Arc Lift Vector**: An upward elevation along the Y-axis prevents link collision with lower-tier device meshes.
- **Link States**:
  - `ACTIVE`: Solid fluorescent teal/blue line with flowing particles.
  - `INACTIVE`: Translucent gray line.
  - `DEGRADED`: Dashed amber line with intermittent packet pulses.
  - `BLOCKED`: Solid red line bisected by a firewall exclusion disc.
  - `UNKNOWN`: Dim dotted white line.

## 2. Protocol Color & Velocity Attribution
Moving flow particles reflect protocol characteristics:
| Protocol | Particle Color | Speed Multiplier | Pulse Frequency |
| :--- | :--- | :--- | :--- |
| **TCP** | `#3B82F6` (Electric Blue) | 1.0x | Medium |
| **UDP** | `#10B981` (Emerald Green) | 1.4x | High (Burst) |
| **ICMP** | `#F59E0B` (Amber Orange) | 0.8x | Low (Ping) |
| **HTTP** | `#06B6D4` (Cyan) | 1.1x | Medium |
| **HTTPS** | `#6366F1` (Indigo/Purple) | 1.1x | High |
| **DNS** | `#EC4899` (Magenta/Pink) | 1.6x | Rapid short bursts |
| **SSH** | `#F97316` (Deep Orange) | 0.9x | Continuous steady |

## 3. Bounded Particle Ring Buffer
To guarantee client stability under 10,000+ packets/sec volumetric attack scenarios:
- Particle allocations are capped to a strict maximum limit (e.g., 500 active particles across the scene).
- Ingested traffic events scale particle velocity and emissive intensity rather than instantiating infinite mesh nodes.