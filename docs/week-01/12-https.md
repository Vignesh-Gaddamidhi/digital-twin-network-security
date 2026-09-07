# Day 5: Hypertext Transfer Protocol Secure (HTTPS)

## 1. Core Security Model
- Transmitted over TCP Port 443.
- Protects HTTP communication using cryptographic guarantees provided by TLS:
  1. **Confidentiality:** Symmetrical session keys (AES-GCM-256) prevent wiretapping.
  2. **Integrity:** MAC (Message Authentication Codes) ensure data cannot be altered in transit.
  3. **Authentication:** X.509 PKI certificates validate server identity.

## 2. Packet Visibility Comparison
| Observation Dimension | HTTP (Port 80) | HTTPS (Port 443) |
|---|---|---|
| Domain Name | Visible in `Host` header | Visible in `SNI` during TLS ClientHello |
| Full URI Path | Fully Visible (`/api/v1/user/10`) | Completely Encrypted |
| Headers & Cookies | Fully Plaintext | Completely Encrypted |
| Body / Form Data | Fully Plaintext | Completely Encrypted |
| Payload Entropy | Low (ASCII Text: 3.0 - 5.0) | High (Random Ciphertext: 7.6 - 7.99) |