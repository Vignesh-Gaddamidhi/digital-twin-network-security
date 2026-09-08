# Day 55: Administrative SSH Traffic Simulation

## 1. Protocol Specifications
- **Transport:** TCP. Destination Port: 22.
- **Application:** `SSH`.
- **Session Lifecycle States:**
  - `REQUESTED`: Initial TCP connection to Port 22, protocol version exchange (`SSH-2.0-OpenSSH`).
  - `AUTHENTICATING`: Key exchange (KEX) and credential challenge (public key, password).
  - `ESTABLISHED`: Authenticated interactive pseudo-terminal session open.
  - `IDLE`: Session open with periodic keep-alive traffic.
  - `CLOSED`: Graceful session teardown via exit/logout (`FIN`).
  - `FAILED`: Authentication failure, port closed, or connection timeout (`RST`).

## 2. Event Payload Contract
```json
{
  "eventId": "evt-ssh-001",
  "simulationId": "sim-001",
  "protocol": "TCP",
  "application": "SSH",
  "sourceDevice": "admin-01",
  "destinationDevice": "server-01",
  "sourcePort": 51420,
  "destinationPort": 22,
  "sessionState": "ESTABLISHED",
  "username": "sysadmin",
  "authMethod": "PUBLIC_KEY",
  "timestamp": "2026-09-08T15:00:00.000000Z"
}