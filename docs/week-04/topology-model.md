# Day 24: Network Topology Model Architecture

## 1. Topological Hierarchy
The Digital Twin represents the entire network fabric using a hierarchical model:
[ Autonomous System / Perimeter WAN ]
│
▼
[ Gateway Router (D004) ]
│
▼
[ Corporate Core Switch (D005) ]
┌────────┼────────┐
▼        ▼        ▼
[ D001 ] [ D002 ] [ D003 ]
Client   Server   Client


## 2. Dynamic Structural Mutability
The topology graph is mutable at runtime:
- **Link Degradation:** When bandwidth saturates or jitter spikes, link properties update dynamically.
- **Micro-Segmentation / Isolation:** In response to high-severity SIEM incidents, the Twin can remove graph edges to simulate host isolation and verify the containment blast radius.