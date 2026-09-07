# Day 10: Scapy Engine Fundamentals

## 1. Declarative Protocol Stacking
Scapy stacks layers using the Python division (`/`) operator:
```python
packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / IP(dst="192.168.1.10") / TCP(dport=80, flags="S") / "GET / HTTP/1.1\r\n\r\n"
2. In-Memory Introspection Methods
packet.show(): Prints hierarchical breakdown with all calculated and explicit fields.

packet.summary(): One-line concise protocol trace.

packet.haslayer(LayerClass): Boolean evaluation for the presence of a specific layer.

bytes(packet): Serializes object tree into wire-format binary octets.

packet.__class__(raw_bytes): Deserializes binary wire data back into typed Scapy layer structures.