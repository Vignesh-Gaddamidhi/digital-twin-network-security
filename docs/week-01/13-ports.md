# Day 4: Port Bindings & Network Socket Abstraction

## 1. Port Classification
- **Well-Known Ports (0 - 1023):** Restricted to privileged system services.
- **Registered Ports (1024 - 49151):** Assigned to specific user application servers.
- **Dynamic / Ephemeral (49152 - 65535):** Client-side outbound random allocation.

## 2. Core Service Directory
| Port | Protocol | Service / Daemon | Security Context |
|---|---|---|---|
| 21 | TCP | FTP (File Transfer) | Plaintext credentials, brute-force target |
| 22 | TCP | SSH (Secure Shell) | Remote administration, key exchange |
| 23 | TCP | Telnet | Insecure legacy plaintext communication |
| 53 | UDP/TCP | DNS (Name Resolution) | Spoofing, DNS cache poisoning, tunneling |
| 80 | TCP | HTTP | Plaintext web traffic |
| 443 | TCP | HTTPS (TLS) | Encrypted transport channel |
| 5432 | TCP | PostgreSQL | Internal data tier, target for lateral movement |
| 6379 | TCP | Redis | In-memory store, unauthorized command execution |