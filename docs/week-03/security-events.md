# Day 18: Security Events vs. Raw Telemetry Logs

## 1. Distinction Matrix
- **Raw Telemetry Log:** An unparsed record of an observed system state or network packet (e.g., standard Nginx access line or Scapy frame summary).
- **Security Event:** A normalized, enriched data record that denotes an action with potential security significance.
- **Security Alert:** A correlated notification generated when one or more security events violate an established policy or match an attack rule.

## 2. Event Severity Classification
- `LOW`: Informational security observations; routine administrative actions.
- `MEDIUM`: Policy drift; port scans targeting non-critical assets; repeated login failures.
- `HIGH`: Confirmed exploit signature; lateral movement activity; unauthorized access to sensitive ports.
- `CRITICAL`: Active root compromise; denial-of-service collapse; ransomware or data exfiltration detected.