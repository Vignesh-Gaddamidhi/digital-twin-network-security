# Capstone Technical Deliverable: The End-to-End Packet Journey

## Unified Traversal: PC1 (`192.168.1.11`) to Production Server (`192.168.1.10:443`)
APPLICATION LAYER (DNS Name Resolution)

User application initiates request to "https://srv-web-01.internal/api/v1/telemetry".

Client resolves hostname: UDP Port 53 query sent to Gateway DNS Server (192.168.1.1).

Resolver returns A record: 192.168.1.10.

TRANSPORT LAYER (TCP Handshake Initiation)

Kernel allocates ephemeral outbound port (51234).

Generates TCP SYN segment:
[Source Port: 51234 | Destination Port: 443 | Seq: 1000 | Flags: [SYN]]

NETWORK LAYER (Subnet Evaluation & IP Routing)

Evaluates: (192.168.1.10 & 255.255.255.0) == (192.168.1.11 & 255.255.255.0).

Evaluates TRUE -> Destination is on the LOCAL LAN.

Gateway routing is bypassed. Packet assembled:
[Source IP: 192.168.1.11 | Destination IP: 192.168.1.10 | Protocol: 6 (TCP) | TTL: 64]

DATA LINK LAYER (ARP Resolution & Frame Assembly)

Host checks local ARP cache for 192.168.1.10.

If missing: Broadcasts ARP Request (FF:FF:FF:FF:FF:FF). Server returns MAC: 00:50:56:FE:01:10.

Frame constructed:
[Dst MAC: 00:50:56:FE:01:10 | Src MAC: 00:50:56:FE:01:11 | EtherType: 0x0800 (IPv4)]

SWITCH BRIDGING FABRIC (Layer-2 Forwarding)

Frame enters Switch D005 on Port 1.

Switch inspects Source MAC -> Maps Port 1 = 00:50:56:FE:01:11 in CAM table.

Switch inspects Destination MAC -> Finds 00:50:56:FE:01:10 bound to Port 2.

Frame forwarded directly out Port 2 (Unicast, no broadcast flooding).

SERVER FIREWALL EVALUATION

Inbound frame reaches Server D002 interface eth0.

Packet inspected against firewall rules:
Matches Rule: ALLOW Protocol=TCP Port=443 -> ACCEPTED.

TCP HANDSHAKE COMPLETION & TLS ESTABLISHMENT

Server kernel dispatches SYN-ACK to PC1 (Seq: 2000, Ack: 1001).

PC1 returns ACK -> Socket state moves to ESTABLISHED.

TLS 1.3 cryptographic handshake negotiates AES-GCM session keys.

Encrypted HTTP application payloads begin bidirectional exchange.
