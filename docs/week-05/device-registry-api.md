# Day 29: Device Registry API Contract

## 1. REST CRUD Endpoints
- `POST /api/v1/twin/registry/devices`: Register new device. Returns 201 Created or 409 Conflict if duplicate.
- `GET /api/v1/twin/registry/devices/{id}`: Retrieve single device by ID. Returns 200 OK or 404 Not Found.
- `GET /api/v1/twin/registry/devices`: List all registered devices with optional zone/type filters.
- `PUT /api/v1/twin/registry/devices/{id}`: Full update of device profile. Returns 200 OK or 404 Not Found.
- `DELETE /api/v1/twin/registry/devices/{id}`: Delete device and purge adjacent connections. Returns 200 OK or 404 Not Found.