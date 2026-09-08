# Phase 5: Router Model & Longest-Prefix Matching
Models Layer 3 packet forwarding behavior:
- Maintains routing tables with destination CIDRs, next-hop gateways, interfaces, and administrative metrics.
- Executes Longest-Prefix Match (LPM) algorithms: specific prefixes (`/28`, `/24`) win over default routes (`0.0.0.0/0`).
- Performs hop-by-hop forwarding simulation and default gateway resolution.