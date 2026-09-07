# Day 38: Zone Segmentation Graph & Perimeter Boundary Engine

## 1. Conceptual Model
Zone segmentation clusters network nodes into discrete security domains characterized by a trust level:
- `INTERNET` (Trust: 0): Untrusted perimeter.
- `DMZ` (Trust: 2): Semi-trusted perimeter for public services.
- `INTERNAL` (Trust: 3): Corporate user subnets, workstations, and local resolvers.
- `DATABASE` (Trust: 4): Restricted data tier storing sensitive relational stores.

## 2. Zone Engine Operations
- `createZone(id, name, trustLevel)`: Instantiates a security domain.
- `deleteZone(id)`: Removes a zone (unassigns member devices).
- `assignDeviceToZone(zone_id, device_id)`: Migrates device into target zone.
- `removeDeviceFromZone(zone_id, device_id)`: Detaches device from zone.
- `getZoneDevices(zone_id)`: Lists all devices belonging to a zone.
- `getZoneConnections(zone_id)`: Lists all internal (intra-zone) and boundary (inter-zone) links.
- `buildZoneGraph()`: Condenses the device topology into a coarse-grained zone transit graph.