# Day 5: Domain Name System (DNS) Mechanics

## 1. Resolution Model
- DNS maps human-readable domain names to logical IP routing endpoints.
- Uses UDP Port 53 for standard lookups (fallback to TCP Port 53 for responses exceeding 512 bytes or zone transfers).
- **Resolver Flow:** Browser Cache -> OS Cache (`ipconfig /displaydns`) -> Local DNS Resolver (Router/DC) -> Root Server -> TLD Server -> Authoritative Nameserver.

## 2. Resource Record Types
- `A`: Maps domain to IPv4.
- `AAAA`: Maps domain to IPv6.
- `CNAME`: Alias to canonical name.
- `TXT`: Text string metadata (frequently abused for Command & Control payload transfers).

## 3. Digital Twin Threat Context
- **DNS Tunneling:** Encoding arbitrary command or exfiltration payloads inside DNS subdomains (e.g., `<base64-blob>.c2.attacker.com`) to bypass firewalls that allow outbound port 53.
- **Cache Poisoning:** Injecting fraudulent mapping entries into a caching resolver to redirect victim nodes to attacker-controlled twin replicas.