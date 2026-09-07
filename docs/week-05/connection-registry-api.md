# Day 31: Connection Registry REST API

- `POST /api/v1/twin/registry/connections`: Create connection. Validates that both endpoints exist in the Device Registry.
- `GET /api/v1/twin/registry/connections/{id}`: Retrieve single connection record by ID.
- `GET /api/v1/twin/registry/connections`: List all connections with optional filtering by `type`, `device_id`, or `status`.
- `PUT /api/v1/twin/registry/connections/{id}`: Update connection parameters (status, latency, bandwidth).
- `DELETE /api/v1/twin/registry/connections/{id}`: Terminate and delete connection from topology.