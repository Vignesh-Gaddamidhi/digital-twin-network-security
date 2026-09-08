# Day 54: DNS Traffic Simulation & Resolution Engine

## 1. Protocol Specifications
- **Transport:** UDP by default (TCP for large payload zone fallbacks). Destination Port: 53.
- **Application:** `DNS`.
- **Query Types:**
  - `A`: Host address (IPv4)
  - `AAAA`: IPv6 address
  - `CNAME`: Canonical name alias
  - `MX`: Mail exchange server
  - `TXT`: Text record metadata (e.g., SPF, token verification)
- **Synthetic Zones:** `*.test`, `internal.test`, `web.internal.test`, `db.internal.test`.

## 2. DNS Event Contract
```json
{
  "eventId": "evt-dns-001",
  "simulationId": "sim-001",
  "sourceDevice": "client-01",
  "destinationDevice": "dns-01",
  "destinationPort": 53,
  "protocol": "UDP",
  "application": "DNS",
  "direction": "OUTBOUND",
  "queryType": "A",
  "domain": "web.internal.test",
  "transactionId": 18921,
  "isResponse": false
}
Response Contract
JSON
{
  "eventId": "evt-dns-002",
  "simulationId": "sim-001",
  "sourceDevice": "dns-01",
  "destinationDevice": "client-01",
  "destinationPort": 53,
  "protocol": "UDP",
  "application": "DNS",
  "direction": "INBOUND",
  "queryType": "A",
  "domain": "web.internal.test",
  "transactionId": 18921,
  "isResponse": true,
  "rcode": "NOERROR",
  "answers": ["192.168.20.10"],
  "ttl": 300
}