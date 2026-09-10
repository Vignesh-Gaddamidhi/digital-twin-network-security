# Day 80: Suricata EVE JSON Pipeline

## 1. Pipeline Stages
1. **SuricataEveCollector:** Ingests EVE lines from streams, files, or API payloads.
2. **EveJsonParser:** Deserializes raw string lines into JSON structures with line-number context.
3. **EveEventValidator:** Verifies required fields (`timestamp`, `event_type`, `src_ip`, `dest_ip`, `proto`) and validates IPv4/IPv6 integrity.
4. **Dead-Letter Error Queue:** Records malformed, non-JSON, or invalid records with error reasons so telemetry is never silently dropped.
5. **EveNormalizer:** Transforms valid records across five core categories (`alert`, `flow`, `dns`, `http`, `tls`) into standard `NormalizedSecurityEvent` models.

## 2. Supported Categories
- **`alert`:** Rule matching, SID, GID, revision, rule category, severity (1–4 mapped to CRITICAL–LOW).
- **`flow`:** Bidirectional byte and packet counters, flow closure metrics.
- **`dns`:** Query hostnames, record types (`A`, `AAAA`, `TXT`, `MX`), response codes.
- **`http`:** HTTP method, virtual host, URL path, HTTP status code.
- **`tls`:** Server Name Indication (SNI), subject DN, issuer, protocol version.