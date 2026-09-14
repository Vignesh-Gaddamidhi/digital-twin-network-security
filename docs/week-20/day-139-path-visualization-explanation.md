# Day 139: Attack Path Visualization & Forensic Explanation

## 1. Directed Visual Representation
Topological network graphs alone do not indicate threat flow. Attack path rendering relies on:
- **Explicit Directional Indicators:** Arrows ($A \to B \to C$) depicting adversary lateral pivoting.
- **Path State Classes:**
  - `POTENTIAL_ATTACK_PATH`: Structurally viable, moderate risk.
  - `HIGH_RISK_PATH`: Traverses high-value services with active vulnerabilities.
  - `CRITICAL_PATH`: Direct reachability to mission-critical crown jewels (`DB-01`).
  - `BLOCKED_PATH`: Visually highlighted in red/amber with active firewall rule annotation.

## 2. Multi-Layer Explanation Synthesis
The forensic explanation engine fuses three distinct evidentiary layers:
1. **ML Attribution (Phase 15):** Why the initial anomaly was flagged (e.g. connection frequency surge).
2. **Contextual Risk (Phase 16):** Why the host is risky (e.g. unpatched RCE vulnerability).
3. **Graph Impact (Phase 17):** Where the adversary can traverse next (e.g. reaches production database).