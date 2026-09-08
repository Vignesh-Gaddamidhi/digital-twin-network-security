# Day 59: Traffic Spike Simulation & Dynamic Twin Metric Coupling

## 1. Volumetric Traffic Curve
Simulates volumetric surges using a multi-phase profile:
- **Baseline Phase:** Steady operational rate (e.g. 100 events/min ≈ 1.67 events/sec).
- **Ramp-Up Phase:** Linear or exponential acceleration toward peak rate.
- **Sustained Spike Phase:** Plateau at peak saturation (e.g. 800 events/min ≈ 13.33 events/sec).
- **Ramp-Down Phase:** Return to baseline rate.
- **Recovery Phase:** System stabilization back at baseline conditions.

## 2. Digital Twin Dynamic State Feedback
As traffic volume surges:
- `networkUtilisation`: Increases linearly with frame volume (e.g., 20% -> 92%).
- `activeConnections`: Scales with connection requests (e.g., 5 -> 40).
- `cpu`: Host CPU consumption tracks socket interrupt pressure (e.g., 25% -> 82%).

## 3. Configuration Contract
```json
{
  "scenarioId": "spike-web-001",
  "affectedDevice": "client-01",
  "targetDevice": "web-01",
  "targetPort": 443,
  "baselineRate": 100,
  "spikeRate": 800,
  "rampUpTime": 2,
  "spikeDuration": 10,
  "rampDownTime": 2
}