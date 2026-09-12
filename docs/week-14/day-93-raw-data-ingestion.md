# Day 93: Raw Traffic Collection & Data Ingestion Engine

## 1. Provenance Invariant (Zero Data Loss)
Raw observations are written to immutable storage before filtering, imputation, or normalization. Every record preserves:
- `rawRecordId`: Deterministic unique identifier (`RAW-XXXXXX`).
- `rawPayload`: Pristine, unmutated source dictionary or text log.
- `source`: Telemetry origin (`SIMULATION`, `SURICATA`, `ZEEK`, `SECURITY_PIPELINE`).
- `sourceFile`: Name or path of the ingested file/stream.
- `originalTimestamp`: Sensor/host event timestamp.
- `ingestionTimestamp`: Ingestion UTC timestamp.

## 2. Non-Destructive Deduplication
Duplicate records are tagged rather than deleted:
- `fingerprint`: SHA-256 hash of `(source, originalTimestamp, endpoints, transport, signature/payload)`.
- `deduplicationStatus`: `ORIGINAL` vs. `DUPLICATE`.
- `duplicateOf`: ID of the primary record if flagged as duplicate.
- Auditing: Retains duplicate counts in `DatasetMetadata` without polluting feature matrices.