# Day 20: Incident Response Lifecycle & Severity Classification

## 1. NIST SP 800-61 Rev 2 Incident Response Framework
1. **Preparation:** Hardening assets, configuring sensor taps, deploying baseline monitors, and training personnel.
2. **Detection & Analysis:** Identifying deviations from nominal traffic, classifying severity, and validating against false positives.
3. **Containment:**
   - *Short-term:* Isolating the compromised host (`D002`) from the virtual switch, dropping egress routes.
   - *Long-term:* Blocking malicious IP subnets on perimeter firewalls.
4. **Eradication:** Terminating rogue socket listeners, patching exploited CVEs (`CVE-2023-38408`), revoking exposed credentials.
5. **Recovery:** Restoring services from trusted images, validating normal CIA scores, re-attaching network links.
6. **Lessons Learned:** Archiving attack PCAPs to retrain anomaly baselines and update detection signatures.

## 2. Severity Classification Matrix
| Severity Band | Qualification Criteria | Automated Digital Twin Action |
|---|---|---|
| **LOW** | Minor policy drift; single port probe on internal non-critical node. | Informational log entry; alert counter incremented. |
| **MEDIUM** | Horizontal scan; authentication failure burst below lockout threshold. | Increased polling frequency; packet capture buffer engaged. |
| **HIGH** | Exploit signature match; unauthorized connection to core server port. | Active alert emitted to SOC; target node flagged `SUSPICIOUS`. |
| **CRITICAL** | Confirmed shell exploit; DDoS saturation; multi-stage kill chain. | Automated containment triggered; target node flagged `COMPROMISED`. |