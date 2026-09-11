# Day 92: Machine Learning Dataset Architecture & Data Sources

## 1. Architectural Principles
- **No Direct Raw Log Training:** Machine learning algorithms must never be trained directly on raw text logs or variable-schema JSON lines. All data is structured into uniform, fixed-width numeric and categorical observation windows.
- **Dual Labeling Taxonomy:**
  - `binaryLabel`: High-level anomaly indicator (`NORMAL`, `ANOMALOUS`).
  - `multiclassLabel`: Specific behavioral/threat class (`NORMAL`, `PORT_SCAN`, `BRUTE_FORCE`, `DOS`, `DNS_ANOMALY`, `BEACONING`, `LATERAL_MOVEMENT`, `DATA_EXFILTRATION`).
- **Separation of Metadata from Features:** Entity identifiers (e.g., `sampleId`, `timestamp`, `sourceDevice`, `destinationDevice`) are recorded for provenance and auditing, but explicitly excluded from training matrices to avoid data leakage and model overfitting to static IPs.
- **Data Leakage Safeguards:** Feature aggregation horizons strictly follow event observation windows without looking into future temporal horizons.

## 2. Telemetry Ingestion Inventory
1. **Phase 7 (Simulation Traffic):** Baseline normal network traffic (HTTP, DNS, SSH, background flows).
2. **Phase 8 (Canonical Scenarios):** 7 controlled attack patterns (`SCN-PORTSCAN-001`, `SCN-BRUTEFORCE-001`, `SCN-DOS-001`, `SCN-DNS-001`, `SCN-BEACON-001`, `SCN-LATERAL-001`, `SCN-EXFIL-001`).
3. **Phase 9 (IDS / NSM):** Suricata EVE alert telemetry and Zeek stateful protocol logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `ssh.log`).
4. **Phase 10 (Pipeline):** Standardized `CanonicalEvent` and `SecurityFeatureVector` sliding-window streams.