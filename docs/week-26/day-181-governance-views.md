# Day 181: Governance, Compliance & Administration Views

## 1. Governance Architecture Overview
The governance layer unifies auditing, compliance reporting, and access management to support enterprise compliance standards (SOC 2, ISO 27001):

                   [Platform Central Core]
                              │
  ┌───────────────────────────┼───────────────────────────┐
  ▼                           ▼                           ▼
[Compliance Reports]     [Forensic Audit Logs]      [Identity & RBAC]
(8 Standard Archetypes)  (Day 174 Audit Trail)      (5 Operational Roles)


## 2. Enterprise RBAC Role Hierarchy
1. `ADMIN`: Full administrative control, system settings, model retraining, and account provisioning.
2. `SECURITY_LEAD`: Incident closure authority, playbook policy overrides, and risk model re-calibration.
3. `SOC_ANALYST`: Alert triage, investigation execution, and safe response simulation dispatch.
4. `AUDITOR`: Read-only access to forensic ledgers, reports, telemetry streams, and compliance posture.
5. `VIEWER`: Read-only overview access to executive dashboards and sanitized 2D/3D topology views.

## 3. Forensic Ledger Integration
Audit views consume the tamper-evident `ForensicAuditEntry` schema from Day 174:
- Captures operator attribution, affected device, previous state $\to$ new state, response action, mode, and outcome.