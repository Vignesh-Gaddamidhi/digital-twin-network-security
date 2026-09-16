# Day 169: Safe Automated Response Simulation Architecture

## 1. Automated Remediation Lifecycle
The response loop is deterministic, non-destructive to real-world hosts, and traceable:

[THREAT / IDS EVENT]
│
▼
[ML PREDICTION + XAI]
│
▼
[CANONICAL RISK SCORE] (P * C * V * I >= Threshold)
│
▼
[RECOMMENDATION ENGINE] ──> Suggests optimal Playbook Action
│
▼
[POLICY ENFORCEMENT & SAFETY GATE] (Checks simulation mode, operator permissions)
│
▼
[CANONICAL DIGITAL TWIN MUTATION] (Graph nodes / edges updated)
│
▼
[IMMUTABLE AUDIT LOG GENERATION]
│
▼
[REAL-TIME WEBSOCKET BROADCAST]
│
┌─────┴─────┐
▼           ▼
2D Canvas   3D WebGL (Isolation wireframe cage / severed link)


## 2. Response Action Taxonomy
- `ISOLATE_DEVICE`: Breaks all network links connected to the target host; sets node security state to `ISOLATED`.
- `BLOCK_CONNECTION`: Modifies firewall link rules between specific source and destination IP pairs; traffic rate drops to 0 bps.
- `DISABLE_SERVICE`: Shuts down vulnerable port (e.g. port 80/443 for CVE-2026-WEB-RCE or 3306 for SQLi) on target host.
- `QUARANTINE_ENDPOINT`: Enforces air-gapped subnet containment on compromised workstation clients.
- `INCREASE_SECURITY_LEVEL`: Escalates inspection profile (e.g., switches link telemetry mode from `NORMAL` to `DEEP_INSPECTION`).
- `MARK_DEVICE_AT_RISK`: Flags device visual aura to orange/amber; restricts lateral privileges without full severance.

## 3. Strict Safety Invariants
1. **Simulation Guardrail**: All actions run in `simulation` mode by default. Real-world execution drivers are strictly decoupled and disarmed.
2. **Deterministic Rollback**: Every simulated action produces a corresponding inverse rollback descriptor to restore baseline state.
3. **Traceable Provenance**: No response executes without binding to a triggering `alertId`, `predictionId`, `riskScore`, and valid `operatorId`.