# Day 160: 3D Attack Paths, Topology Filtering & Seamless 2D ↔ 3D Switching

## 1. 3D Attack Path Highlighting Model
When an attack path is selected:
- Traversed nodes retain full opacity, emit high-intensity emissive pulses, and render an outer waypoint ring.
- Traversed connection splines illuminate with an animated attack pulse (`#EF4444` or `#F59E0B`).
- Non-traversed nodes and links are dimmed to `0.2` opacity rather than removed from the scene, preserving spatial context.

   ATTACKER-EXT (Entry)
         │  [Traversed Link: Glowing Crimson Spline]
         ▼
      WEB-01 (Pivot)
         │  [Traversed Link: Glowing Crimson Spline]
         ▼
      DB-01 (Crown Jewel Target)

## 2. Non-Destructive Filtering Pipeline
Filtering operations must adhere to the single-source-of-truth invariant:
- Filters alter only `mesh.isVisible` and `mesh.material.opacity`.
- The Digital Twin graph state (`attack_path_graph.nodes` and `attack_path_graph.edges`) is never pruned, mutated, or deleted by UI view filters.

## 3. Bidirectional 2D ↔ 3D State Synchronization
Viewport switching preserves operational context through a shared state contract:
       SHARED VIEWPORT STATE (ViewportSyncState)
├── activeViewMode: "2D" | "3D"
├── selectedDeviceId: str | None
├── selectedPathId: str | None
├── activeFilters: FilterCriteria
└── timeRange: "5m" | "15m" | "30m" | "1h" | "6h" | "24h"

Switching from 2D to 3D automatically focuses the camera on the active device/path, while switching from 3D to 2D centers and zooms the 2D pan/zoom canvas on the matching node coordinates.