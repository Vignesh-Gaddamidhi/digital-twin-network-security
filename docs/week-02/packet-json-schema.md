# Day 11: Normalized Security Event JSON Schema

Each parsed packet is normalized into this schema for ML feature engineering and storage:

```json
{
  "$schema": "[http://json-schema.org/draft-07/schema#](http://json-schema.org/draft-07/schema#)",
  "title": "NormalizedPacketEvent",
  "type": "object",
  "required": ["timestamp", "packet_index", "source_ip", "destination_ip", "protocol", "packet_length"],
  "properties": {
    "timestamp": { "type": "string", "format": "date-time" },
    "packet_index": { "type": "integer" },
    "source_mac": { "type": "string" },
    "destination_mac": { "type": "string" },
    "source_ip": { "type": "string" },
    "destination_ip": { "type": "string" },
    "ip_ttl": { "type": "integer" },
    "protocol": { "type": "string", "enum": ["TCP", "UDP", "ICMP", "OTHER"] },
    "detected_application": { "type": "string", "enum": ["DNS", "HTTP", "TLS", "UNKNOWN"] },
    "source_port": { "type": ["integer", "null"] },
    "destination_port": { "type": ["integer", "null"] },
    "tcp_flags": { "type": ["string", "null"] },
    "packet_length": { "type": "integer" },
    "payload_entropy": { "type": "number" },
    "payload_preview": { "type": ["string", "null"] }
  }
}