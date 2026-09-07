# Day 20: Network Anomaly Detector Architecture Specification

## 1. Processing Pipeline
[ Packet / PCAP Stream ]
│
▼
[ Windowed Feature Collector ] ──► Extracts: PPS, BPS, Unique Ports, Unique IPs, Protocol Ratios
│
▼
[ Statistical Baseline Engine ] ──► Compares against Historical (Mean, StdDev) Profile
│
▼
[ Threshold & Z-Score Classifier ]
├── Z <= 3.0  ──► Nominal (Pass)
└── Z >  3.0  ──► Anomaly Alert Event ──► SIEM Correlator ──► Digital Twin Containment


## 2. Design Tenets
- **Lightweight Non-Blocking Execution:** Computes sliding statistical metrics with minimal CPU footprint prior to ML model inference.
- **Explainability:** Emits explicit evidence strings detailing which feature deviated (e.g., `PPS_EXCEEDED_3_SIGMA: observed 85 pps, baseline 12.4 +/- 3.1`).