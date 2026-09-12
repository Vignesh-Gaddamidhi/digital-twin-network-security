# Day 97: Train/Test Split & Anti-Leakage Partitioning

## 1. Cybersecurity Temporal & Group Leakage Risks
In network intrusion detection, naive uniform random splitting generates artificially inflated validation scores because packets and flows from the same connection or coordinated attack run end up in both training and test sets.

To ensure realistic generalization, Day 97 enforces:
1. **Temporal Isolation (`TEMPORAL`):**
   - Training: Observations from earlier scenario intervals $[T_0, T_{\text{split}})$.
   - Testing: Observations from later scenario intervals $[T_{\text{split}}, T_{\text{end}}]$.
   - Invariant: $\max(T_{\text{train}}) \le \min(T_{\text{test}})$.
2. **Group-Aware Isolation (`GROUP`):**
   - Grouping identifier: `simulation_run_id` or `session_key`.
   - Invariant: $\text{Groups}(\text{Train}) \cap \text{Groups}(\text{Test}) = \emptyset$.
3. **Stratified Group-Aware Strategy (`STRATIFIED_GROUP`):**
   - Evaluates rare attack classes (`BRUTE_FORCE_LIKE`, `EXFILTRATION_LIKE`) and allocates entire scenario run groups to preserve class frequencies across train and test partitions.

## 2. Row Lineage Metadata Preservation
Every split row preserves provenance metadata:
- `datasetVersion`: Active ML data generation release (e.g., `v1.0.0`).
- `split`: Partition assignment (`TRAIN` or `TEST`).
- `splitStrategy`: Strategy applied (`TEMPORAL`, `GROUP`, `STRATIFIED`).
- `runId` / `groupId`: Execution instance identifier.
- `scenarioId`: Scenario catalog identifier.