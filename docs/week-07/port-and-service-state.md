# Day 47: Port & Service Daemon Runtime State Engine

## 1. Port States
Every tracked port entity implements a Layer 4 socket definition:
- `OPEN`: Actively accepting connections (`LISTEN` socket).
- `CLOSED`: Responsive to probes but no service daemon bound (`RST` emitted).
- `FILTERED`: Packet dropped or unreachable due to firewall policy.
- `UNKNOWN`: Unprobed or indeterminate socket status.

## 2. Service States
Daemon processes running on host endpoints:
- `RUNNING`: Daemon is active, healthy, and servicing requests.
- `STOPPED`: Process deliberately shut down.
- `DEGRADED`: Daemon is active but impaired (e.g., thread pool exhaustion, 5xx rate high).
- `FAILED`: Process crashed, segfaulted, or core-dumped.
- `UNKNOWN`: State indeterminate.

## 3. Structural Port-Service Binding
Port 443 (TCP)  <── bound to ──>  Service: HTTPS (nginx v1.24)  <── running on ──>  WEB-01
Port 5432 (TCP) <── bound to ──>  Service: PostgreSQL (v16.1)   <── running on ──>  DB-01

Stopping a service flags the corresponding port listener as inactive/unavailable, directly notifying the reachability and impact propagation engines.