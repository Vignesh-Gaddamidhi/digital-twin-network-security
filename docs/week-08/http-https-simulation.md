# Day 53: HTTP & HTTPS Traffic Simulation

## 1. Application-Layer Modeling
Web traffic runs on top of the established TCP transport layer:
- **Plaintext HTTP (Port 80):** Fully inspectable request/response headers, paths, methods, and status codes.
- **Encrypted HTTPS (Port 443):** Encrypted application envelope. Models TLS records, encrypted payload byte distributions, and directional metadata without inspecting real payload secrets.

## 2. Web Traffic Profile Parameters
- `requestRate`: Requests per second.
- `statusDistribution`: Probabilistic mapping of HTTP response status codes (e.g. 90% 200 OK, 8% 404 Not Found, 2% 500 Server Error).
- `requestSize` / `responseSize`: Byte size boundaries for headers and response bodies.
- `paths`: List of simulated URI routes (`/`, `/products`, `/login`, `/api/health`).

## 3. Normalized Event Schema
```json
{
  "eventId": "evt-http-001",
  "simulationId": "sim-001",
  "sourceDevice": "client-01",
  "destinationDevice": "web-01",
  "protocol": "HTTPS",
  "destinationPort": 443,
  "application": "WEB",
  "direction": "OUTBOUND",
  "method": "GET",
  "path": "/products",
  "statusCode": 200,
  "requestBytes": 482,
  "responseBytes": 3840
}