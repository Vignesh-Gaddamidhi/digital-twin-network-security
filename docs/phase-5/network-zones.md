# Phase 5: Network Zones & Segmentation
Models coarse-grained security perimeters:
- `INTERNET` (Trust: 0): Untrusted public WAN.
- `DMZ` (Trust: 2): Semi-trusted perimeter for public services (Web servers).
- `INTERNAL` (Trust: 3): Corporate clients, internal resolvers, and management.
- `DATABASE` (Trust: 4): High-security data tier with strict backend-only access.