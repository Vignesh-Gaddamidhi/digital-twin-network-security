# Day 5 Deliverable: DNS -> TCP -> TLS/HTTPS Packet Flow Lifecycle

## 1. End-to-End Packet Transaction Flow

When an endpoint on a local network fetches `https://api.internal.network/telemetry`:
Step 1: DNS Query (UDP 53)
Client (192.168.1.11) ──────────► DNS Server (192.168.1.1)

Frame: [Ethernet II | IPv4 | UDP | DNS Query "api.internal.network" (A)]

Response: "api.internal.network = 192.168.1.10" (TTL: 300)

Step 2: TCP Handshake (TCP 443)
Client (192.168.1.11:51234) ────► Web Server (192.168.1.10:443)

[SYN]      Seq=0

[SYN-ACK]  Seq=0, Ack=1

[ACK]      Seq=1, Ack=1

Step 3: TLS 1.3 Cryptographic Handshake (TCP 443)

Client sends [ClientHello] with Cipher Suites and SNI "api.internal.network".

Server responds [ServerHello] with ECDH public key share and X.509 Certificate.

Master secret and symmetric keys derived. Handshake confirmed with [Finished].

Step 4: Encrypted HTTPS Transaction (TCP 443)

[Application Data] encrypted via AES-GCM (Entropy > 7.8).

Web Server decrypts payload, processes GET /telemetry, returns encrypted 200 OK.

Step 5: TCP Connection Teardown

Bidirectional exchange of [FIN, ACK] segments.


## 2. Plaintext vs. Ciphertext Packet Field Visibility
- **DNS (UDP 53):** FQDN name queries are fully visible in plaintext unless DNS-over-HTTPS (DoH) is enforced.
- **HTTP (TCP 80):** Method (`GET`), URI path, Query Parameters, Headers, Cookies, and JSON Payloads are fully observable by IDS tools.
- **HTTPS (TCP 443):** Target IP, Target Port, and SNI (host name) are observable. All HTTP request verbs, query strings, headers, and bodies are fully encrypted.