# Day 13: Network Monitoring System Architecture

## 1. Role in the Digital Twin
The Network Monitoring System sits between physical/simulated network segments and the Digital Twin state graph:
- Ingests raw frames or flow telemetry.
- Normalizes disparate packet headers into consistent network events.
- Emits real-time rate metrics (packets/sec, bytes/sec) and top-talker tables.
- Feeds dynamic connection records into the Digital Twin memory model.