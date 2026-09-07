# Day 18: Security Operations Center (SOC) Incident Workflows

## 1. The Incident Response Lifecycle (NIST SP 800-61 Rev 2)
1. **Preparation:** Establishing sensor tap coverage, logging baselines, and detection rule suites.
2. **Detection & Analysis:** Identifying deviations from normal operational baselines; triage and validation by Tier 1 analysts.
3. **Containment:** Preventing lateral spread through network segmentation and endpoint isolation (simulated via Digital Twin firewall rules).
4. **Eradication:** Removing malicious processes, unauthorized artifacts, and compromised accounts.
5. **Recovery:** Restoring systems to clean operational states and confirming nominal telemetry returns.
6. **Lessons Learned:** Integrating post-incident indicators into new correlation rules and ML feature datasets.

## 2. Operational Metrics
- **Mean Time to Detect (MTTD):** Average duration between adversary initial entry and analyst alert validation.
- **Mean Time to Respond (MTTR):** Average duration between alert generation and successful containment action.