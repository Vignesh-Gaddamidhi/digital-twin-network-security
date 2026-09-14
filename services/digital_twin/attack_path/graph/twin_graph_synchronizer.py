import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[4]
GRAPH_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
SYNCED_GRAPH_FILE = GRAPH_ARTIFACTS_DIR / "twin_synced_graph.json"

from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.security_zone_models import (
    NetworkZoneEnum, ReachabilityStateEnum, SecurityControlPolicy, DEFAULT_SECURITY_POLICIES
)

class TwinSecurityGraphSynchronizer:
    """Synchronizes Digital Twin devices, connections, zones, vulnerabilities, and security controls with AttackPathGraph."""

    def __init__(self, artifacts_dir: Path = GRAPH_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.security_policies: List[SecurityControlPolicy] = list(DEFAULT_SECURITY_POLICIES)
        self.device_store: Dict[str, Dict[str, Any]] = {}
        self.connection_store: Dict[str, Dict[str, Any]] = {}
        self._seed_default_twin_state()

    def _seed_default_twin_state(self):
        """Pre-seeds canonical Digital Twin device topology."""
        self.device_store = {
            "ATTACKER-EXT": {
                "deviceId": "ATTACKER-EXT",
                "hostname": "adversary.external.net",
                "ip": "198.51.100.24",
                "mac": "00:50:56:C0:00:08",
                "os": "Kali Linux 2026",
                "nodeType": NodeTypeEnum.ATTACKER,
                "zone": NetworkZoneEnum.INTERNET,
                "assetCriticality": "VERY_LOW",
                "services": [],
                "ports": [],
                "vulnerabilities": [],
                "securityState": "NORMAL",
                "riskScore": 0.0
            },
            "CLIENT-01": {
                "deviceId": "CLIENT-01",
                "hostname": "client-01.corp.internal",
                "ip": "192.168.10.101",
                "mac": "00:1A:2B:3C:4D:01",
                "os": "Windows 11 Enterprise",
                "nodeType": NodeTypeEnum.CLIENT,
                "zone": NetworkZoneEnum.INTERNAL,
                "assetCriticality": "LOW",
                "services": ["SMB", "RDP"],
                "ports": [445, 3389],
                "vulnerabilities": [],
                "securityState": "NORMAL",
                "riskScore": 5.76
            },
            "WEB-01": {
                "deviceId": "WEB-01",
                "hostname": "web-01.dmz.internal",
                "ip": "192.168.20.80",
                "mac": "00:1A:2B:3C:4D:80",
                "os": "Ubuntu 24.04 LTS",
                "nodeType": NodeTypeEnum.WEB_SERVER,
                "zone": NetworkZoneEnum.DMZ,
                "assetCriticality": "HIGH",
                "services": ["HTTP", "HTTPS", "SSH"],
                "ports": [80, 443, 22],
                "vulnerabilities": ["CVE-2026-WEB-RCE"],
                "securityState": "AT_RISK",
                "riskScore": 60.80
            },
            "DB-01": {
                "deviceId": "DB-01",
                "hostname": "db-01.secure.internal",
                "ip": "192.168.30.10",
                "mac": "00:1A:2B:3C:4D:0A",
                "os": "RHEL 9.4",
                "nodeType": NodeTypeEnum.DATABASE,
                "zone": NetworkZoneEnum.DATABASE,
                "assetCriticality": "CRITICAL",
                "services": ["MYSQL", "POSTGRESQL"],
                "ports": [3306, 5432],
                "vulnerabilities": ["CVE-2026-SQLI"],
                "securityState": "NORMAL",
                "riskScore": 69.60
            },
            "DNS-SERVER-01": {
                "deviceId": "DNS-SERVER-01",
                "hostname": "dns-01.infra.internal",
                "ip": "192.168.1.53",
                "mac": "00:1A:2B:3C:4D:53",
                "os": "Debian 12",
                "nodeType": NodeTypeEnum.DNS_SERVER,
                "zone": NetworkZoneEnum.INTERNAL,
                "assetCriticality": "MEDIUM",
                "services": ["DNS"],
                "ports": [53],
                "vulnerabilities": [],
                "securityState": "NORMAL",
                "riskScore": 5.76
            }
        }

        self.connection_store = {
            "CONN-01": {
                "connectionId": "CONN-01",
                "sourceDevice": "ATTACKER-EXT",
                "destinationDevice": "WEB-01",
                "protocol": "TCP",
                "destinationPort": 443,
                "service": "HTTPS",
                "status": "ESTABLISHED"
            },
            "CONN-02": {
                "connectionId": "CONN-02",
                "sourceDevice": "CLIENT-01",
                "destinationDevice": "WEB-01",
                "protocol": "TCP",
                "destinationPort": 22,
                "service": "SSH",
                "status": "ESTABLISHED"
            },
            "CONN-03": {
                "connectionId": "CONN-03",
                "sourceDevice": "WEB-01",
                "destinationDevice": "DB-01",
                "protocol": "TCP",
                "destinationPort": 3306,
                "service": "MYSQL",
                "status": "ESTABLISHED"
            },
            "CONN-04": {
                "connectionId": "CONN-04",
                "sourceDevice": "CLIENT-01",
                "destinationDevice": "DNS-SERVER-01",
                "protocol": "UDP",
                "destinationPort": 53,
                "service": "DNS",
                "status": "ESTABLISHED"
            },
            "CONN-05": {
                "connectionId": "CONN-05",
                "sourceDevice": "CLIENT-01",
                "destinationDevice": "DB-01",
                "protocol": "TCP",
                "destinationPort": 3306,
                "service": "MYSQL",
                "status": "ATTEMPTED"
            }
        }

    def evaluate_security_controls(
        self,
        source_device_id: str,
        destination_device_id: str,
        destination_port: int,
        protocol: str
    ) -> Tuple[ReachabilityStateEnum, str]:
        src_dev = self.device_store.get(source_device_id)
        dst_dev = self.device_store.get(destination_device_id)

        if not src_dev or not dst_dev:
            return ReachabilityStateEnum.UNKNOWN, "Source or destination device unknown."

        src_zone = src_dev["zone"]
        dst_zone = dst_dev["zone"]

        # Check explicit security control policies
        for pol in self.security_policies:
            if pol.sourceZone == src_zone and pol.destinationZone == dst_zone:
                if pol.reachabilityState == ReachabilityStateEnum.BLOCKED:
                    return ReachabilityStateEnum.BLOCKED, f"Blocked by {pol.controlId}: {pol.name}"
                if destination_port in pol.allowedPorts:
                    return ReachabilityStateEnum.REACHABLE, f"Permitted by {pol.controlId}: {pol.name}"
                else:
                    return ReachabilityStateEnum.BLOCKED, f"Port {destination_port} not permitted by {pol.controlId}"

        # Intra-zone traffic permitted by default
        if src_zone == dst_zone:
            return ReachabilityStateEnum.REACHABLE, f"Permitted: Intra-zone communication within {src_zone.value}"

        return ReachabilityStateEnum.RESTRICTED, f"Default restriction between {src_zone.value} and {dst_zone.value}"

    def full_synchronization(self):
        """Synchronizes all Digital Twin devices and connections into AttackPathGraph."""
        attack_path_graph.clear()

        # 1. Sync Nodes
        for dev_id, d in self.device_store.items():
            node = AttackPathNode(
                nodeId=dev_id,
                deviceId=dev_id,
                nodeType=d["nodeType"],
                hostname=d["hostname"],
                ipAddresses=[d["ip"]],
                deviceType=d.get("os", "Standard Device"),
                zone=d["zone"].value if isinstance(d["zone"], NetworkZoneEnum) else str(d["zone"]),
                assetCriticality=d["assetCriticality"],
                vulnerabilities=list(d.get("vulnerabilities", [])),
                exposedPorts=list(d.get("ports", [])),
                services=list(d.get("services", [])),
                securityState=d.get("securityState", "NORMAL"),
                riskScore=float(d.get("riskScore", 0.0)),
                reachable=True
            )
            attack_path_graph.add_node(node)
            # Sync initial continuous risk state in risk_state_engine
            from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
            risk_state_engine.record_risk_observation(
                device_id=dev_id,
                risk_score=float(d.get("riskScore", 0.0)),
                prediction_id=f"PRED-INIT-{dev_id}"
            )

        # 2. Sync Edges
        for conn_id, c in self.connection_store.items():
            src = c["sourceDevice"]
            dst = c["destinationDevice"]
            port = c["destinationPort"]
            proto = c["protocol"]

            reach_state, rationale = self.evaluate_security_controls(src, dst, port, proto)

            edge = AttackPathEdge(
                edgeId=conn_id,
                sourceNode=src,
                destinationNode=dst,
                connectionId=conn_id,
                protocol=proto,
                destinationPort=port,
                service=c.get("service", "TCP"),
                reachable=(reach_state == ReachabilityStateEnum.REACHABLE),
                securityControl=rationale,
                status=reach_state.value
            )
            attack_path_graph.add_edge(edge)

        self._persist_sync_state()

    # ==================== REACTIVE MUTATION HOOKS ====================

    def sync_device(self, device_data: Dict[str, Any]):
        dev_id = device_data["deviceId"]
        self.device_store[dev_id] = device_data
        self.full_synchronization()

    def sync_connection(self, connection_data: Dict[str, Any]):
        conn_id = connection_data["connectionId"]
        self.connection_store[conn_id] = connection_data
        self.full_synchronization()

    def remove_connection(self, connection_id: str):
        if connection_id in self.connection_store:
            del self.connection_store[connection_id]
            self.full_synchronization()

    def update_device_ports(self, device_id: str, new_ports: List[int]):
        if device_id in self.device_store:
            self.device_store[device_id]["ports"] = new_ports
            self.full_synchronization()

    def update_device_vulnerabilities(self, device_id: str, new_vulns: List[str]):
        if device_id in self.device_store:
            self.device_store[device_id]["vulnerabilities"] = new_vulns
            self.full_synchronization()

    def isolate_device(self, device_id: str):
        """Simulates automated security quarantine by severing connections."""
        if device_id in self.device_store:
            self.device_store[device_id]["securityState"] = "QUARANTINED"
            # Remove all incoming/outgoing connections
            to_remove = [
                cid for cid, c in self.connection_store.items()
                if c["sourceDevice"] == device_id or c["destinationDevice"] == device_id
            ]
            for cid in to_remove:
                del self.connection_store[cid]
            self.full_synchronization()

    def _persist_sync_state(self):
        data = {
            "deviceCount": len(self.device_store),
            "connectionCount": len(self.connection_store),
            "syncedGraph": attack_path_graph.snapshot()
        }
        with open(SYNCED_GRAPH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

twin_graph_synchronizer = TwinSecurityGraphSynchronizer()