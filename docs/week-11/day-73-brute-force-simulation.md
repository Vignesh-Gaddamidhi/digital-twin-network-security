# Day 73: SCN-BRUTEFORCE-001 (Repeated Authentication Failure Simulation)

## 1. Objective
Model high-frequency failed credential attempts from `CLIENT-01` against `SERVER-01` without actual password guessing or credential dumps.

## 2. Scenario Contract
- **Scenario ID:** `SCN-BRUTEFORCE-001`
- **Category:** `BRUTE_FORCE`
- **Severity:** `HIGH`
- **Target:** `SERVER-01`
- **Preconditions:**
  1. `SERVER-01` exists in registry.
  2. Authentication service exists (SSH on port 22 or Web Auth on port 443).
  3. Simulated target user account exists in simulation context (`admin`, `service_account`, etc.).
- **Expected Indicators:**
  - `HIGH_AUTH_FAILURE_RATE`: Rate of failed attempts exceeds threshold (> 3.0 failures/sec).
  - `REPEATED_AUTH_FAILURES`: Total count of consecutive failures exceeds threshold (> 8.0).
  - `SHORT_FAILURE_INTERVAL`: Mean inter-attempt delay is compressed (< 0.5s).
  - `UNUSUAL_AUTH_PATTERN`: Failure ratio exceeds baseline (> 0.85).
- **Recovery:**
  - Reset host failed login counters, clear hanging auth sessions, restore baseline telemetry.