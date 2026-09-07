# Day 12: Baseline Normal Behavioral Profiles

## 1. Standard Enterprise Behavioral Profiles

### A. Web Browsing Profile (`WEB_BROWSING`)
1. Client issues DNS query for host domain to local resolver (UDP Port 53).
2. Resolver returns A record with server IP.
3. Client executes 3-Way Handshake with Server (TCP Port 80/443).
4. Client issues HTTP `GET /index.html` or TLS ClientHello.
5. Server responds with 200 OK or TLS ServerHello.
6. Graceful 4-Way TCP Teardown (`FIN-ACK`).

### B. DNS Heartbeat Profile (`DNS_HEARTBEAT`)
- Periodic UDP lookups for internal infrastructure endpoints (`srv-db-01.internal`).
- Uniform time distribution with subtle Gaussian jitter.

### C. ICMP Echo Health-Check (`ICMP_PING`)
- Low-frequency ping echo requests (`Type 8`) and replies (`Type 0`) between workstations and gateway routers.