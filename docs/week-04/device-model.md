# Day 23: Device Digital Twin Architectural Model

## 1. Domain Model Overview
The Device Digital Twin is an object-oriented representation of physical and virtual computing nodes. 
Unlike static configuration databases (CMDBs), the Device Twin maintains runtime states:
- Active TCP/UDP socket connections.
- Ephemeral port allocations.
- Real-time CPU / memory exhaustion metrics.
- Dynamic CIA Triad health scores.
- Associated vulnerabilities (CVEs) and effective exposure levels.

## 2. Core Entities
- **DeviceEntity:** Master aggregate root containing hardware profile, operating system, and interfaces.
- **DeviceInterface:** Physical or virtual network interface card (NIC) bound to a subnet.
- **PortEntity:** Layer 4 transport listener state (TCP/UDP).
- **ServiceEntity:** Application daemon managing an open port.
- **OperatingSystem:** Platform identity, kernel release, and patch tier.