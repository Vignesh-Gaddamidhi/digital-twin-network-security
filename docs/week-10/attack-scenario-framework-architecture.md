# Day 65: Attack Scenario Framework Architecture

## 1. System Overview
The Attack Scenario Framework provides a unified execution engine for representing attack-like behaviors safely within the Digital Twin environment.

## 2. Canonical Scenario State Machine
[CREATED] ──► [VALIDATING] ──► [READY] ──► [RUNNING] ──► [DETECTED]
│              │             │            │               │
▼              ▼             ▼            ▼               ▼
[FAILED]       [FAILED]     [CANCELLED]   [CANCELLED]   [RECOVERING]
│
▼
[COMPLETED]


## 3. Generic Scenario Model Schema
Every scenario implements:
- `scenarioId`: Standardized identifier (`SCN-PORTSCAN-001`, `SCN-BRUTEFORCE-001`, etc.)
- `name`: Human-readable identifier.
- `description`: Detailed technical explanation.
- `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `target`: Target device/interface and affected endpoints.
- `preconditions`: Prerequisites verified prior to execution.
- `trafficPattern`: Parametric instructions for the synthetic generator.
- `expectedIndicators`: Observable telemetry anomalies expected during detection.
- `recovery`: Actions to heal the Digital Twin back to its baseline.
- `metadata`: Seed, author, version, and tags.