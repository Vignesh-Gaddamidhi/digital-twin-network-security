# Day 15: Vulnerability Analysis & CVE Registry

## 1. Vulnerability Classes
- **Software Flaws:** Buffer overflows, remote code execution bugs, and memory corruption bugs identified by CVEs (Common Vulnerabilities and Exposures).
- **Misconfigurations:** Default passwords, missing firewall filters, unsegmented subnets, services listening on `0.0.0.0` instead of `127.0.0.1`.
- **Architectural Weaknesses:** Single points of failure, lack of encryption in transit, broadcast domains without dynamic ARP inspection.

## 2. CVSS (Common Vulnerability Scoring System)
Vulnerabilities are quantified via CVSS v3.1 base metrics:
- Low: `0.1 - 3.9`
- Medium: `4.0 - 6.9`
- High: `7.0 - 8.9`
- Critical: `9.0 - 10.0`