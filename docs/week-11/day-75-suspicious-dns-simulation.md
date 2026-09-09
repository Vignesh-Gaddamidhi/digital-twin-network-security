# Day 75: SCN-DNS-001 (Suspicious DNS Behaviour Simulation)

## 1. Objective
Simulate abnormal DNS traffic patterns (burst frequency, TXT record clustering, subdomain entropy, and repeated lookups) directed at `DNS-01` using reserved `.test` test zones (`example.test`, `internal.test`, `service.test`, `random.test`).

## 2. Scenario Contract
- **Scenario ID:** `SCN-DNS-001`
- **Category:** `SUSPICIOUS_DNS`
- **Severity:** `MEDIUM`
- **Target:** `DNS-01`
- **Preconditions:**
  1. `DNS-01` exists in registry.
  2. DNS service exists on port 53.
  3. Network path between `CLIENT-01` and `DNS-01` exists.
- **Expected Indicators:**
  - `UNUSUAL_DNS_FREQUENCY`: DNS query emission rate exceeds threshold (> 10 queries/sec).
  - `UNUSUAL_DNS_QUERY_TYPE`: Anomaly in query record types (e.g. TXT record percentage > 30%).
  - `REPEATED_DNS_REQUESTS`: Multiple identical requests sent in tight succession (> 8 queries).
  - `UNUSUAL_DNS_DISTRIBUTION`: Subdomain diversity / entropy skew indicative of tunneling or DGA.
- **Twin State Degradation:**
  - DNS Query Rate surges: ~45 queries/sec
  - DNS event history ledger appends 80+ records
  - DNS-01 host utilisation increases to 65%
- **Recovery:**
  - Halt pattern generator, clear DNS transaction cache, restore network utilisation to 20%.