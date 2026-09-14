# Day 131: Risk Levels, Explanation & XAI Integration

## 1. Risk Tier Definitions & Actionable Guidance
| Risk Level | Score Range | Operational Description | Recommended Action |
|---|---|---|---|
| `LOW` | $[0.0, 25.0)$ | Limited predicted threat and/or low-impact asset context. | Continue routine monitoring. No immediate intervention required. |
| `MEDIUM` | $[25.0, 50.0)$ | Moderate combined threat involving non-critical assets or mitigated flaws. | Schedule routine investigation and verify telemetry anomalies. |
| `HIGH` | $[50.0, 75.0)$ | Significant predicted threat targeting critical assets or unpatched flaws. | Prioritize investigation; prepare isolation or rate-limiting playbooks. |
| `CRITICAL` | $[75.0, 100.0]$ | Severe threat probability against mission-critical assets with active vulnerabilities. | Trigger immediate security response; evaluate automated containment. |

## 2. Risk Assessment Confidence vs. Model Prediction Confidence
- **Model Confidence (`categoryConfidence`):** Probability certainty of the categorical classifier ($P(Y=k \mid x)$).
- **Risk Assessment Confidence (`riskAssessmentConfidence`):** Reliability of the environmental context:
  - `HIGH`: All 4 factors ($T, A, V, I$) known with confirmed Digital Twin asset registration.
  - `MEDIUM`: Asset or vulnerability status inferred via heuristic uncertainty defaults.
  - `LOW`: One or more environmental attributes missing or using conservative baselines.
  - `UNKNOWN`: Unregistered target asset or missing model telemetry.