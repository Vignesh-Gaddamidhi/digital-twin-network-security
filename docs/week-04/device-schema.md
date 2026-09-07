# Day 23: Canonical Device Digital Twin JSON Schema

```json
{
  "$schema": "[http://json-schema.org/draft-07/schema#](http://json-schema.org/draft-07/schema#)",
  "title": "DeviceDigitalTwin",
  "type": "object",
  "required": ["id", "hostname", "type", "role", "interfaces", "operational_state", "security_state"],
  "properties": {
    "id": { "type": "string" },
    "hostname": { "type": "string" },
    "type": { "type": "string", "enum": ["WORKSTATION", "SERVER", "ROUTER", "SWITCH", "FIREWALL"] },
    "role": { "type": "string" },
    "criticality": { "type": "number", "minimum": 1.0, "maximum": 10.0 },
    "os": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "version": { "type": "string" },
        "architecture": { "type": "string" },
        "kernel_release": { "type": "string" },
        "patch_level": { "type": "string" }
      }
    },
    "interfaces": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "interface_id": { "type": "string" },
          "ip_address": { "type": "string" },
          "mac_address": { "type": "string" },
          "subnet_cidr": { "type": "string" },
          "assigned_via_dhcp": { "type": "boolean" }
        }
      }
    },
    "ports": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "port_number": { "type": "integer" },
          "protocol": { "type": "string", "enum": ["TCP", "UDP"] },
          "state": { "type": "string", "enum": ["OPEN", "FILTERED", "CLOSED"] },
          "bound_service": { "type": "string" },
          "is_exposed": { "type": "boolean" }
        }
      }
    },
    "services": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "version": { "type": "string" },
          "status": { "type": "string", "enum": ["RUNNING", "STOPPED", "DEGRADED"] },
          "port": { "type": "integer" },
          "protocol": { "type": "string" }
        }
      }
    },
    "operational_state": { "type": "string", "enum": ["ONLINE", "DEGRADED", "OFFLINE"] },
    "security_state": { "type": "string", "enum": ["HEALTHY", "SUSPICIOUS", "COMPROMISED", "ISOLATED"] }
  }
}