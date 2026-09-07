# Day 23: Device Identity & Network Identification

## 1. Unique Identifiers
- **Device ID:** Canonical immutable string across the entire twin lifecycle (`D001` through `D005` or UUID).
- **Hostname:** RFC 1123 compliant network identifier (e.g., `srv-web-01`).
- **Asset Type:** Functional classification:
  - `WORKSTATION`: End-user client nodes (ephemeral connections, high phishing susceptibility).
  - `SERVER`: Infrastructure and application providers (listening services, public exposure).
  - `ROUTER`: Multi-interface Layer 3 forwarding engines (routing tables, NAT translations).
  - `SWITCH`: Layer 2 bridging fabrics (VLANs, CAM tables).
  - `FIREWALL`: State inspection and traffic policy enforcement points.
- **Operational Role:** Business context (`WEB_SERVER`, `FINANCE_CLIENT`, `GATEWAY_NAT`, `CORE_FABRIC`).
- **Asset Criticality:** Normalized scale $[1.0, 10.0]$ quantifying business and mission impact.