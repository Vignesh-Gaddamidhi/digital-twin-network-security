# Day 30: Device Configuration Engine & Dynamic Mutability

## 1. Core Responsibilities
The `DeviceConfigurationEngine` provides atomic, validated configuration changes to registered network devices:
- **Interface Management:** Provision, bring UP/DOWN, or reconfigure Layer 2/3 interfaces.
- **IP Addressing:** Assign or revoke primary and secondary IPv4/IPv6 addresses with duplicate collision detection.
- **Service & Port Control:** Bind or unbind listening network daemons and toggle TCP/UDP port listener states.
- **Zone Reclassification:** Shift devices between `INTERNAL`, `DMZ`, `EXTERNAL`, and `MANAGEMENT` zones (triggering instant attack surface updates).
- **Route Injection:** Add or withdraw static routing table entries.

## 2. Configuration Mutation Primitives
| Method | Description | Side Effects |
|---|---|---|
| `configureInterface()` | Create or update NIC parameters | Syncs interfaces and IP/MAC arrays |
| `assignIPAddress()` | Bind IPv4/IPv6 to interface | Re-evaluates routing subnet membership |
| `removeIPAddress()` | Revoke IP from interface | Cleans active socket descriptors |
| `addService()` | Install and bind application daemon | Expands exposed service registry |
| `removeService()` | Terminate application daemon | Removes related listening ports |
| `openPort()` | Open Layer 4 port listener | Increases attack surface ingress count |
| `closePort()` | Close Layer 4 port listener | Decreases attack surface ingress count |
| `changeZone()` | Shift device network security zone | Recomputes exposure factor and dynamic risk |