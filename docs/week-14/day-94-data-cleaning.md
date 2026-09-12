# Day 94: Data Cleaning & Preprocessing Engine

## 1. Feature-Specific Missing Value Policies
Never blanket-fill missing values with zero; semantic absence differs from numeric zero:
- `destinationPort`: Missing/ICMP defaults to `0` (system reservation for non-ported traffic).
- `bytes` / `packets`: Missing defaults to `0` / `1` minimum observed wire unit.
- `flowDuration`: Missing defaults to `0.001s` (single-packet instantaneous transaction).
- `dnsFrequency`: Defaults to `0.0` for non-DNS protocols (`TCP`, `ICMP`), but preserves `None` or flags missing resolution if protocol is `UDP:53`.
- `interArrivalTime` / `intervalVariance`: Defaults to `0.0` for isolated single-packet flows.
- `service`: Inferred from destination port (`80 -> HTTP`, `443 -> HTTPS`, `22 -> SSH`, `53 -> DNS`).

## 2. Invalid Values vs. Legitimate Cyber Outliers
- **Fatal Data Errors (Reject):** Negative byte/packet counts, ports outside `[0, 65535]`, unparseable timestamps, invalid IP formats, negative duration.
- **Extreme Statistical Outliers (Preserve):** High packet rates ($> 100{,}000\,\text{pkts/s}$), asymmetric byte ratios ($> 10{,}000\times$), high failed connection rates. These are **retained** because they are canonical signals of volumetric DoS, scans, and exfiltration.