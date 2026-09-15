# Dashboard Architecture
The Security Simulation Dashboard interfaces directly with FastAPI endpoints and WebSocket channels. It consumes:
1. Live network topology state from the synchronized Digital Twin graph.
2. Real-time telemetry streams (packets/sec, bytes/sec, active connections).
3. Supervised ML classifications and LSTM time-series early warnings.
4. SHAP explainability feature attributions.
5. Contextual multiplicative risk scores ($T \times A \times V \times I$).
6. Directed attack path traversals and firewall enforcement points.