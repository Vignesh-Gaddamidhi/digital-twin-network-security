# Day 157: 3D Devices, CSS2D/CSS3D Labels & Raycaster Mesh Selection

## 1. Device Geometric Archetypes
Each canonical device type maps directly to a distinct 3D visual geometry representation:
- **INTERNET**: Icosahedron mesh with rotating outer wireframe ring.
- **FIREWALL**: Shield-shaped chamfered prism with glowing red perimeter lines.
- **ROUTER**: Cylindrical disc with dual cross-flow directional conduits.
- **SWITCH**: Low-profile rectangular box with multi-port array LED indicators.
- **WEB_SERVER**: Dual-tier rack chassis with front ventilation arrays.
- **DATABASE**: Triple-stacked cylinder structure representing data storage plates.
- **DNS_SERVER**: Hexagonal prism with vertical antenna beacon.
- **CLIENT**: Desktop workstation monitor wedge and keyboard base plate.
- **UNKNOWN**: Octahedral faceted generic mesh with yellow caution highlight.

## 2. World-Space Billboard Label System
Labels are mapped via CSS2D/CSS3D overlay renderers:
- World coordinate vectors $(x, y, z)$ are projected to screen viewport coordinates $(u, v)$.
- Labels maintain constant pixel density and orientation regardless of camera tilt or rotation.
- Configurable display filters: Hostname, Device Type, IP address, and security posture badges.

## 3. Raycaster Mesh Picking & Selection State Machine
1. User clicks canvas $(x_{\text{mouse}}, y_{\text{mouse}})$.
2. Normalized Device Coordinates (NDC) are calculated:
   $$x_{\text{ndc}} = \frac{2x}{W} - 1, \quad y_{\text{ndc}} = 1 - \frac{2y}{H}$$
3. Three.js `Raycaster` intersects visible bounding volumes (`boundingRadius`).
4. Resolved `deviceId` queries the backend Twin device registry.
5. Mesh changes visual state (`UNSELECTED` -> `SELECTED`), and camera smoothly transitions to `FOCUSED_DEVICE`.