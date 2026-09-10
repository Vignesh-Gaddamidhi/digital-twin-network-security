# Day 82: Zeek Fundamentals & Protocol Log Integration

## 1. Architectural Distinction: Suricata vs. Zeek
- **Suricata (NIDS/IPS):** Rule-driven alert detection engine. Identifies known CVE exploits, malicious payloads, and alert signatures.
- **Zeek (NSM Platform):** Transactional network audit ledger. Emits structured protocol-level accounting logs regardless of whether an alert was triggered.

## 2. Core Zeek Log Streams
- **`conn.log`:** Network connection state, duration, byte counters (`orig_bytes`, `resp_bytes`), packet counts, connection history flags (`S0`, `SF`, `RSTO`).
- **`dns.log`:** DNS queries, query classes, response codes (`NOERROR`, `NXDOMAIN`), answers list.
- **`http.log`:** Request methods (`GET`, `POST`), host headers, URI requests, referrer, user-agent, response codes (`200`, `404`).
- **`ssl.log` (TLS):** Cipher suites, negotiated TLS versions, server names (SNI), subject validation.
- **`ssh.log`:** SSH client/server authentication versions, cipher negotiations, inferred auth success flags.

## 3. Schema & Format Flexibility
Zeek outputs logs in two standard formats:
1. **Zeek TSV / Ascii:** Tab-separated values with `#fields` header and `-` representing null/unset values.
2. **Zeek Streaming JSON:** Single-line JSON objects with standard field naming (`id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`).