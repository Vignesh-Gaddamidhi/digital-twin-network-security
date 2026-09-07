# Day 6 Deliverable: The End-to-End Packet Journey Analysis

## 1. Unified Packet Traversal Lifecycle
Tracing an HTTPS request from Engineering PC1 (`192.168.1.11`) to an external web host (`example.com` at `93.184.216.34`):
## 2. Core Security Takeaways for Digital Twins
- **Perimeter Modeling:** The Digital Twin needs both structural link maps and stateful connection tables to simulate packet drops accurately.
- **NAT Concealment:** External threat actors only see the translated public IP (`203.0.113.5`). Internal lateral movement simulations require un-translating NAT tables to determine the true compromised host.