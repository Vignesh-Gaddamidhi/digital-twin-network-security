# Day 156: Three.js WebGL Foundation, Scene Graph & Camera Control System

## 1. WebGL Pipeline & Layer Architecture
The 3D canvas is powered by Three.js with an isolated, hierarchical scene graph:

NetworkTwin3D
│
├── WebGLRenderer (PBR, Antialiasing, DPR clamping)
├── PerspectiveCamera (FOV: 45°, Near: 0.1, Far: 2000.0)
├── Lighting Rig (Hemisphere, Key Directional, Fill, Ambient)
├── Orbit / Interaction Controls (Rotate, Pan, Zoom, Reset)
├── Scene Environment (Infinite Polar Grid, Skybox gradient)
└── Render Loop (60 FPS requestAnimationFrame with delta-time throttling)


## 2. Camera State Machine
The camera system supports five explicit operational modes:
- `DEFAULT`: Isometric overview framing all network zones.
- `USER_CONTROLLED`: Free orbit, pan, and zoom via mouse/touch interaction.
- `FOCUSED_DEVICE`: Smooth exponential lerp toward a clicked device mesh.
- `FOCUSED_PATH`: Elevated vantage point framing an active multi-hop attack traversal.
- `RESETTING`: Animated return transition to default coordinates `(0, 180, 320)`.

## 3. WebGL Resource Disposal Lifecycle
To prevent GPU memory leaks during dashboard tab switching:
1. Stop `requestAnimationFrame` loop.
2. Traverse scene graph and call `geometry.dispose()` on all meshes.
3. Call `material.dispose()` and texture unbinding.
4. Force `renderer.dispose()` and explicitly lose WebGL context (`WEBGL_lose_context`).