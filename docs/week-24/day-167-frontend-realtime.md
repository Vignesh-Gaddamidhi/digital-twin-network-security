# Day 167: Next.js Real-Time Store, 2D/3D Synchronization & Failure States

## 1. Universal Single-Store Architecture
Under no circumstances do the 2D and 3D views maintain separate WebSocket consumers or independent state registries:
             ❌ INADEQUATE                   ✅ UNIFIED ARCHITECTURE
      WebSocket ──> 2D Local Store                 WebSocket
      WebSocket ──> 3D Local Store                     │
   (Risk of UI state divergence)                       ▼
                                              RealtimeStoreEngine
                                            ┌──────────┴──────────┐
                                            ▼                     ▼
                                        2D Canvas             3D Canvas

## 2. Decoupled Failure Modes & Health States
- **Transport Disconnection**: WebSocket link dropped (`DISCONNECTED` / `RECONNECTING`). Last-known visual state is preserved; live pulses halt; reconnection backoff runs in the background.
- **Global Stale Data**: WebSocket is open (`CONNECTED`), but elapsed time since the last heartbeat exceeds threshold ($\Delta t > 2.0\text{s}$). Marked `STALE DATA`.
- **Per-Device Stale Telemetry**: The platform is live, but a specific device (e.g. `WEB-01`) has not emitted telemetry frames for $> 10.0\text{s}$. The device badge transitions to `STALE` while the rest of the canvas updates normally.
- **Backend Error**: Sanitized error frame (`ERROR`) triggers a top-level alert toast without tearing down canvas buffers.

## 3. Selection & Filter Continuity
When toggling between 2D and 3D views:
- `selectedDeviceId` remains bound to the inspection drawer.
- `activeFilters` (`deviceTypeFilter`, `securityStateFilter`, `riskLevelFilter`, `visibilityPreset`) persist seamlessly.