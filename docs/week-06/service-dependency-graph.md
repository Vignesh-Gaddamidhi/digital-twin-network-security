# Day 40: Network Services & Application Dependency Graph

## 1. Concept Formulation
While network topology captures how packets travel across wires and switches, the **Service Dependency Graph** captures how application processes depend on each other:
$$G_{\text{service}} = (V_s, E_s)$$

Where:
- $V_s$ = Unique service instances running on devices: `(device_id, service_name)`.
- $E_s$ = Directed functional dependencies: `(source_service) -> (target_service)`.

## 2. Service Dependency Entity
```json
{
  "sourceDevice": "web-01",
  "sourceService": "web-app",
  "destinationDevice": "db-01",
  "destinationService": "postgresql",
  "protocol": "TCP",
  "port": 5432,
  "status": "ACTIVE",
  "criticality": "HIGH"
}
3. Impact Propagation Engine
Given a failed or compromised service $S_{\text{root}}$:
Reverse-traverse the dependency graph (find all ancestors / predecessors).
Trace the upstream cascade:
$$\text{Affected}(S_{\text{root}}) = \{ s \in V_s \mid \exists \text{ path from } s \text{ to } S_{\text{root}} \}$$
Quantify blast-radius criticality score and identify degraded business processes.