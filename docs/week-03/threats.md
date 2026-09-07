# Day 15: Threat Categorization & Actor Profiles

## 1. Threat Taxonomy
A threat represents an actor or circumstance with the capability to cause harm.
- **External Network Threats:** Unauthenticated actors probing ingress perimeter boundaries via SYN scans, exploit scripts, and DDoS amplification.
- **Internal / Lateral Movement Threats:** Compromised internal workstations (`D001`, `D003`) attempting lateral SSH pivots or database brute-force sweeps.
- **Automated Bot / Worm Scanners:** Stateless, high-frequency probes cycling through ephemeral ports and default credential dictionaries.

## 2. Threat Actor Modeling in Digital Twins
The Digital Twin simulates threat actors via parameterized traffic generators:
- **Capability Level:** Scripter, Advanced Adversary, Automated Scanner.
- **Position:** External WAN (`203.0.113.x`) or Internal Impairment (`192.168.1.99`).
- **Target Vector:** Specific ports (`80`, `443`, `22`, `5432`) and known CVE identifiers.