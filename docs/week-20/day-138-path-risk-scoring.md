# Day 138: Vulnerability-Aware & Risk-Aware Attack Path Scoring

## 1. Weakest-Link Composite Path Risk Policy
To prevent mathematical attenuation over multi-hop traversals, attack path risk combines:
1. **$R_{\max}$ (35%):** Maximum node risk score along the transit path.
2. **$C_{\text{target}}$ (25%):** Normalized criticality weight of the final destination node ($0.20 \dots 1.00$).
3. **$V_{\text{path}}$ (20%):** Service-relevant vulnerability factor across traversed edges.
4. **$I_{\text{attack}}$ (20%):** Attack impact potential for the modeled adversary vector.
5. **$\alpha_{\text{reach}}$ (Multiplier):** Reachability coefficient:
   - `POSSIBLE`: $1.00$
   - `PARTIALLY_REACHABLE`: $0.50$
   - `BLOCKED`: $0.15$

## 2. Vulnerability Relevance Classification
- `RELEVANT`: Active CVE matching the specific port and service used on the ingress edge.
- `POSSIBLY_RELEVANT`: Active CVE on the host, but service relationship is indirect.
- `NOT_RELEVANT`: CVE bound to an uncontacted port or already remediated (`PATCHED`).
- `UNKNOWN`: Unverified vulnerability context.

## 3. Path Prioritization & Ranking
Discovered paths are sorted in descending order of `pathRiskScore`. The highest-risk path is designated as the primary containment target.