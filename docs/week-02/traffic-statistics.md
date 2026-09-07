# Day 13: Traffic Statistics & Rate Derivation

## 1. Metric Calculations
- **Packets Per Second (PPS):**
  $$\text{PPS} = \frac{\Delta \text{Packets}}{\Delta t}$$
- **Bytes Per Second (BPS / Throughput):**
  $$\text{BPS} = \frac{\Delta \text{Bytes}}{\Delta t}$$
- **Protocol Distribution:**
  $$\%_{\text{Proto}} = \left( \frac{\text{Packets}_{\text{Proto}}}{\text{Total Packets}} \right) \times 100$$
- **Top Talkers:** Ranked list of source and destination IP addresses by total cumulative byte and flow counts.