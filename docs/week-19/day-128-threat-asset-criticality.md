# Day 128: Threat Probability & Asset Criticality Engine

## 1. Defensive Threat Ingress Validation
Incoming threat probabilities from ML inference engines must be verified against strict numerical constraints before entering the risk pipeline:
- Accepted: Floating-point scalars $P \in [0.0, 1.0]$.
- Rejected with `ValueError` / HTTP 400: $P < 0.0$, $P > 1.0$, `NaN`, `Infinity`, `null`.

## 2. Prediction Provenance Preservation
To satisfy auditability requirements, the Risk Engine tracks:
- `predictionId`: Unique inference UUID.
- `modelName`: Classifier identifier (e.g. `RandomForest`, `XGBoost`).
- `modelVersion`: Model artifact version.
- `featureVersion`: Schema version of feature vector.
- `datasetVersion`: Training dataset partition identifier.
- `predictionTimestamp`: UTC timestamp of original model prediction.

## 3. Asset Criticality Model
Each Digital Twin network node is classified under standard operational criticality tiers:
- `VERY_LOW` (0.20): Test clients, ephemeral sandbox nodes.
- `LOW` (0.40): Standard user workstations (`CLIENT-01`).
- `MEDIUM` (0.60): Internal services (`DNS Server`).
- `HIGH` (0.80): Demilitarized zone application servers (`Web Server`).
- `CRITICAL` (1.00): Database servers (`DB-01`), domain controllers, core routing backbones.