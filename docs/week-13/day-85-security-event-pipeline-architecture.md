# Day 85: Security Event Pipeline Architecture & Lifecycle Contracts

## 1. Domain Separation
- **Packet:** Raw network frame or raw log record with timestamps, endpoints, transport, and payloads.
- **Event:** A semantically structured observation derived from packets or IDS telemetry.
- **Feature Vector:** Measurable behavioral rates (packet/byte rates, failed handshakes, unique port counts, entropy).
- **Detection:** Heuristic or rule-based interpretation of anomalies with associated confidence scores.
- **Risk Assessment:** Dynamic scoring based on exploit likelihood, impact severity, and asset criticality.
- **Alert:** An actionable notification dispatched to the SOC alert store and applied to the Digital Twin.

## 2. Pipeline State Lifecycle
The pipeline executes a deterministic, observable state transition sequence:
1. `RECEIVED`: Input ingested into pipeline envelope.
2. `PARSED`: Deserialized into typed schema.
3. `NORMALIZED`: Conformed to `NormalizedSecurityEvent`.
4. `FEATURES_EXTRACTED`: Feature vector computed over telemetry windows.
5. `DETECTED`: Analyzed by behavioral and signature detectors.
6. `RISK_ASSESSED`: Likelihood x Impact computed against target assets.
7. `ALERT_CREATED`: Formatted into `ActionableSecurityAlert`.
8. `STORED`: Persisted to Alert Store and reflected in Digital Twin posture.
9. `FAILED`: Terminal error state capturing stage failure reasons without crashing the runner.