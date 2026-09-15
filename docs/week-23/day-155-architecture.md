# Day 155: Enterprise 3D Digital Twin Architecture & Twin-State Contract

## 1. Executive Summary & Source-of-Truth Rule
The 3D visualization layer is strictly an interactive projection of the Digital Twin state. There is never a "3D Twin" separate from a "2D Twin."
DIGITAL TWIN ENGINE (FastAPI)
                   [Single Source of Truth]
                              │
     ┌────────────────────────┴────────────────────────┐
     ▼                                                 ▼
2D Canvas UI (D3 / SVG)                    3D Scene (Three.js / WebGL)

Coordinate space (X, Y)                  - Coordinate space (X, Y, Z)

CSS Badge styling                        - PBR Mesh Shaders & Particle Trails

Side-drawer inspection                   - 3D Gizmo Orbit/Pan/Select


## 2. Twin State Contract vs. Visualization State
To prevent UI presentation attributes from polluting security domain models, the architecture strictly separates:
- **Canonical Twin State**: Read-only device inventory, IP/MAC bindings, OS, services, exposed ports, CVSS vulnerabilities, live telemetry, multiplicative risk scores ($P \times C \times V \times I$), and reachable attack traversals.
- **3D Visualization State**: Transient rendering metadata including 3D world coordinates $(x, y, z)$, Euler rotation, mesh scale, hover/selection flags, particle emitters, and camera viewing vectors.

## 3. 3D Scene Layer Hierarchy
The Three.js scene graph is structured into isolated functional layers:
1. `EnvironmentLayer`: Skybox, directional key/fill lights, ambient occlusion, ground grid.
2. `NetworkNodeLayer`: Instanced geometric meshes representing network devices.
3. `LinkLayer`: Spline curves representing physical and logical network links.
4. `TrafficLayer`: GPU-accelerated particle systems animating flow density and packet rates.
5. `SecurityStateLayer`: Dynamic halo glows, state aura shaders, and containment badges.
6. `AttackPathLayer`: Glowing directional spline paths highlighting active traversals.
7. `LabelLayer`: CSS2D/CSS3D HTML overlays projecting readable device tags into world space.
8. `InteractionLayer`: Raycasting, mesh picking, selection outlines, and camera focus transitions.