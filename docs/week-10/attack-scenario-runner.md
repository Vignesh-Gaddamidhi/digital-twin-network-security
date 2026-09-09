# Day 71: Generic Attack Scenario Runner Architecture

## 1. Unified Orchestration Lifecycle
The `AttackScenarioRunner` executes the end-to-end security simulation lifecycle:
1. `loadScenario(scenario)`: Loads definition into memory.
2. `validateScenario()`: Runs structural and environment precondition audits.
3. `initializeScenario()`: Resets clocks, initializes execution status token.
4. `startScenario()`: Transitions to `RUNNING`.
5. `generateEvents()`: Delegates packet generation to the Traffic Pattern Engine.
6. `detectIndicators()`: Evaluates telemetry metrics against expected indicators.
7. `recoverScenario()`: Applies the configured `ScenarioRecoveryPlan`.
8. `verifyRecovery()`: Audits Digital Twin to confirm baseline restoration.
9. `exportScenarioResults()`: Serializes `ScenarioResult` to disk.

## 2. Complete Result Schema
```json
{
  "scenarioId": "SCN-PORTSCAN-001",
  "runId": "run-atk-...",
  "startTime": "2026-09-09T08:00:00Z",
  "endTime": "2026-09-09T08:00:10Z",
  "eventsGenerated": 15,
  "indicatorsObserved": ["UNUSUAL_PORT_ACTIVITY"],
  "alertsGenerated": ["ALERT-PORT-SPREAD"],
  "riskScore": 34.0,
  "affectedDevices": ["web-01"],
  "stateChanges": {"port8080": "OPEN -> CLOSED"},
  "recoveryStatus": "VERIFIED_RESTORED",
  "finalState": "COMPLETED"
}