# Day 20: Statistical Baseline Methodology & Profiling

## 1. Cold-Start Profiling Procedure
1. Run standard behavioral traffic generator (`WEB_BROWSING`, `DNS_HEARTBEAT`, `ICMP_PING`) in benign state for $N = 50$ consecutive time slices.
2. Ingest windowed metrics into the baseline storage profile (`baseline_profile.json`).
3. Compute $\mu_f$ and $\sigma_f$ across every feature $f \in F$.
4. Lock nominal reference state before executing attack vectors or live network sniffing.