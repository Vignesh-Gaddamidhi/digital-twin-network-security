# Day 34: Endpoints, Service Modeling & Application Dependencies

## 1. Canonical Endpoint Specifications

| Hostname | Role | IP Address | Operating System | Listening Services | Open Ports | Zone |
|---|---|---|---|---|---|---|
| `WEB-SERVER-01` | `WEB_SERVER` | `192.168.20.10` | Ubuntu Linux | `nginx`, `nginx-ssl` | 80, 443 | `DMZ` |
| `DB-SERVER-01` | `DATABASE` | `192.168.20.20` | Ubuntu Linux | `postgresql` | 5432 | `INTERNAL` |
| `DNS-SERVER-01` | `DNS_SERVER` | `192.168.20.30` | Linux | `bind9 / dnsmasq` | 53 | `INTERNAL` |
| `CLIENT-01` | `WORKSTATION` | `192.168.30.10` | Windows 11 Enterprise | `workstation-client` | None | `INTERNAL` |

## 2. Application Dependency Graph
Application services form directed dependency chains:
$$\text{ServiceDependency}(S_A \to S_B) = \langle \text{SourceDevice}, \text{TargetDevice}, \text{TargetPort}, \text{Protocol}, \text{DependencyType} \rangle$$

- **`UPSTREAM_CLIENT`**: Client application consuming an API or web service.
- **`BACKEND_DATASTORE`**: Business tier querying persistence stores.
- **`INFRASTRUCTURE_CORE`**: System-level dependency (DNS, NTP, Kerberos).