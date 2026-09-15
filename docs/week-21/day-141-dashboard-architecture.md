# Day 141: Dashboard Architecture & UI Foundation

## 1. Presentation Layer Role
The Security Simulation Dashboard is the primary operational presentation layer of the Digital Twin. Rather than displaying decoupled mock data, it consumes live state contracts from FastAPI endpoints:
- Digital Twin graph topology and device inventory
- Real-time packet throughput and protocol distribution
- IDS security events and ML attack classification
- SHAP explainability and feature attributions
- Contextual multi-factor risk scores ($T \times A \times V \times I$)
- Directed attack paths and firewall enforcement points

## 2. Component Lifecycle States
Every dashboard card and widget must handle:
- `LOADING`: Skeleton loaders during asynchronous data fetch.
- `LOADED`: Active live telemetry rendering.
- `EMPTY`: Clean fallback when zero events or paths are present.
- `ERROR`: Diagnostic message with an automated retry hook.
- `REFRESHING`: Subtle status indicators during background polling.
- `UNAVAILABLE`: Offline banner if the Twin API is unreachable.