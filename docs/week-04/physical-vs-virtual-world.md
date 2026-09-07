# Day 22: Physical vs. Virtual World Mapping Specification

| Physical / Emulated Network Entity | Digital Twin Virtual Counterpart | Synchronized State Attributes |
|---|---|---|
| **Workstation 1 (`192.168.1.11`)** | `Twin-Device: D001` | IP, MAC, DHCP Lease, Active Ephemeral Ports, CIA Score |
| **Production Server (`192.168.1.10`)** | `Twin-Device: D002` | Nginx/OpenSSH daemons, Listening Ports 80/443/22, CVE-2023-38408, Risk Score |
| **Finance Workstation (`192.168.1.12`)** | `Twin-Device: D003` | Criticality (6.0), Subnet association, Active sessions |
| **Gateway Router (`192.168.1.1`)** | `Twin-Device: D004` | Dual-NIC interfaces (eth0/eth1), NAT Tables, Forwarding Tables |
| **Core Switch Fabric** | `Twin-Device: D005` | VLAN trunk mappings, CAM table bindings, Link latency metrics |
| **Raw Ethernet/IP Wire Packets** | `NetworkEvent / Telemetry Flow` | 5-tuple, protocol flags, byte entropy, packet arrival rates |
| **Physical Threat Actor** | `Simulated Threat Entity` | Tactic progression (Recon -> Exploit), Capability level |