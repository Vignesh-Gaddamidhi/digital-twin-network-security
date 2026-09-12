# Day 98: Feature Normalization, Final Dataset Generation & Week 14 Integration

## 1. Zero-Leakage Normalization Invariant
To preserve the scientific integrity of Phase 12 machine learning evaluations:
- Normalization scalers are strictly fitted on `TRAIN` observations:
  $$\mu_j = \frac{1}{N_{\text{train}}} \sum_{i=1}^{N_{\text{train}}} x_{i,j}$$
  $$\sigma_j = \sqrt{\frac{1}{N_{\text{train}}} \sum_{i=1}^{N_{\text{train}}} (x_{i,j} - \mu_j)^2}$$
- Test features are transformed strictly using training statistics $(\mu_j, \sigma_j)$:
  $$z_{i,j}^{\text{test}} = \frac{x_{i,j}^{\text{test}} - \mu_j}{\max(\sigma_j, 10^{-6})}$$
- Test observations are never seen during parameter estimation.

## 2. Canonical Matrix Representation
- **Predictor Matrix $X$ (20 Numerical Features):**
  1. `packet_rate`
  2. `bytes`
  3. `bytes_per_second`
  4. `connection_frequency`
  5. `port_22_ratio`
  6. `port_53_ratio`
  7. `port_80_ratio`
  8. `port_443_ratio`
  9. `port_other_ratio`
  10. `unique_destination_ports`
  11. `flow_duration`
  12. `tcp_ratio`
  13. `udp_ratio`
  14. `icmp_ratio`
  15. `failed_connections`
  16. `failed_connection_rate`
  17. `dns_queries`
  18. `dns_frequency`
  19. `destination_diversity`
  20. `unique_destination_ratio`
- **Target Matrices $y$:**
  - `binary_label`: `NORMAL` (0), `ANOMALOUS` (1).
  - `multiclass_label`: `NORMAL`, `PORT_SCAN`, `BRUTE_FORCE_LIKE`, `DOS_LIKE`, `DNS_ANOMALY`, `BEACONING`, `LATERAL_MOVEMENT_LIKE`, `EXFILTRATION_LIKE`.
- **Contextual Metadata:** Retained in storage for line-by-line traceability back to raw packets and simulation runs.