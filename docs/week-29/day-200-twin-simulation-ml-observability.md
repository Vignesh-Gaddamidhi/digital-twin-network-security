# Day 200: Digital Twin, Simulation & ML Observability

## 1. Digital Twin Synchronization Paths
The Digital Twin graph state synchronization is instrumented across three primary pathways:
1. `sim_redis_twin`: Simulation attack events transit via Redis Streams into the Twin graph.
2. `twin_postgres`: Asynchronous state snapshots committed to persistent PostgreSQL storage.
3. `twin_ws_soc`: Real-time state mutations broadcasted via WebSocket to client SOC dashboards.

Monitored metrics:
- `twin_updates_total` / `twin_update_failures_total`: Total applied vs. rejected mutations.
- `devices_tracked`: Current active network nodes in the topology model.
- `active_connections`: Current monitored edge connections in the topology graph.
- `state_transitions_total` / `state_transition_failures_total`: State engine transition accounting.

## 2. Attack Simulation Scenarios
Simulations are partitioned across 13 canonical scenarios:
- `NORMAL`
- `TRAFFIC_SPIKE`
- `CONNECTION_ANOMALY`
- `PORT_ANOMALY`
- `PROTOCOL_ANOMALY`
- `REPEATED_CONNECTION`
- `PORT_SCAN`
- `BRUTE_FORCE_LIKE`
- `DOS_LIKE`
- `DNS_ANOMALY`
- `BEACONING`
- `LATERAL_MOVEMENT_LIKE`
- `EXFILTRATION_LIKE`

Tracked signals: `simulation_runs_active`, `simulation_runs_total`, `simulation_runs_completed`, `simulation_runs_failed`, `simulation_events_total`.

## 3. ML Inference & Prediction Latency
Measures prediction performance across model versions and attack categories:
- `ml_inference_latency_seconds`: Latency histogram capturing average, $p_{50}$, $p_{95}$, and $p_{99}$.
- `predictions_total{version, category}` / `predictions_failed_total`: Total classifications vs. failures.
- `predictions_high_confidence_total`: Predictions where confidence $\ge 0.85$.
- `predictions_low_confidence_total`: Predictions where confidence $< 0.65$ (flagged for human-in-the-loop review).

## 4. Dynamic ML Engine Health State
- `HEALTHY`: Model artifacts loaded, latency $< 1.5\text{s}$, error rate $\le 5\%$.
- `DEGRADED`: Latency $> 1.5\text{s}$ or error rate between $5\%$ and $30\%$.
- `ERROR`: Unhandled exception rate $> 30\%$.
- `UNAVAILABLE`: Model artifact file missing from storage.

## 5. XAI & Quantitative Risk Breakdown
- `xai_explanations_total` / `xai_failures_total`: TreeSHAP calculation volume and failure count.
- `risk_calculations_total` / `risk_calculation_failures_total`: Composite risk evaluations.
- `risk_calculations_by_severity{severity}`: Stratified counter across `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.