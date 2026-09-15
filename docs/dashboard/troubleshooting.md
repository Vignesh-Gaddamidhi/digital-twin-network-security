# Troubleshooting & Operational Guide
- **Subsystem Staleness**: If $\Delta t > 5.0\text{s}$, the dashboard displays a `STALE` badge. Check backend event loop throughput.
- **WebSocket Disconnections**: Automatic reconnect backoff runs every 1,000ms.
- **Port Conflicts**: Ensure FastAPI runs on port 8000 and the development server on port 3000.