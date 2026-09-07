# Day 6: Layer-3 Routing Fundamentals & Forwarding Tables

## 1. Core Routing Concepts
- **Router:** Layer-3 device terminating collision and broadcast domains.
- **Routing Table:** In-memory lookup database matching destination subnets via Longest Prefix Match (LPM).
- **Default Route (`0.0.0.0/0`):** Catch-all egress gateway for non-local traffic.
- **Metric / Cost:** Metric value determining preferred route selection when redundant links exist.

## 2. Frame Rewriting Across L3 Hops
When a packet traverses a router hop:
- **IP Header:** Source and Destination IP remain unchanged (unless NAT is active). TTL decrements by 1. Checksum updates.
- **Ethernet Frame:** Completely stripped and rebuilt. Source MAC becomes the router's egress interface MAC; Destination MAC becomes the next-hop router or destination endpoint MAC.