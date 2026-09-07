# Day 18: Canonical SecurityEvent Data Contract

The centralized SIEM and Digital Twin ingestion pipeline enforces the following standardized schema:

```json
{
  "event_id": "SEC-EVT-a1b2c3d4e5f6",
  "timestamp": "2026-09-07T12:30:00.000000Z",
  "source_device_id": "D001",
  "destination_device_id": "D002",
  "source_ip": "192.168.1.11",
  "destination_ip": "192.168.1.10",
  "source_port": 51234,
  "destination_port": 22,
  "protocol": "TCP",
  "event_type": "AUTHENTICATION_BRUTE_FORCE",
  "severity": "HIGH",
  "confidence": 0.95,
  "detection_source": "SURICATA_IDS_ENGINE",
  "details": {
    "cve_targeted": "CVE-2023-38408",
    "rule_id": 200002
  }
}