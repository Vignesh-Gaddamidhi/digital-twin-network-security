import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

ROOT_DIR = Path(__file__).resolve().parents[4]
GRAPH_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
GRAPH_SNAPSHOT_FILE = GRAPH_ARTIFACTS_DIR / "graph_snapshot.json"

from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge, AttackPath
)

class AttackPathGraph:
    """Security-aware directed graph modeling network topology, services, and attack reachability."""

    def __init__(self, artifacts_dir: Path = GRAPH_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.nodes: Dict[str, AttackPathNode] = {}
        self.edges: Dict[str, AttackPathEdge] = {}
        self.adjacency: Dict[str, List[str]] = {}  # source -> [destinations]
        self._initialize_default_topology()

    def _initialize_default_topology(self):
        """Initializes canonical Digital Twin lab topology graph."""
        self.clear()

        # 1. Register Canonical Nodes
        self.add_node(AttackPathNode(
            nodeId="ATTACKER-EXT",
            deviceId="ATTACKER-EXT",
            nodeType=NodeTypeEnum.ATTACKER,
            hostname="adversary.external.net",
            ipAddresses=["198.51.100.24"],
            deviceType="External Threat Actor",
            zone="INTERNET",
            assetCriticality="VERY_LOW",
            reachable=True
        ))

        self.add_node(AttackPathNode(
            nodeId="CLIENT-01",
            deviceId="CLIENT-01",
            nodeType=NodeTypeEnum.CLIENT,
            hostname="client-01.corp.internal",
            ipAddresses=["192.168.10.101"],
            deviceType="User Workstation",
            zone="USER_LAN",
            assetCriticality="LOW",
            exposedPorts=[80, 443],
            services=["HTTP-CLIENT", "HTTPS-CLIENT"],
            reachable=True
        ))

        self.add_node(AttackPathNode(
            nodeId="WEB-01",
            deviceId="WEB-01",
            nodeType=NodeTypeEnum.WEB_SERVER,
            hostname="web-01.dmz.internal",
            ipAddresses=["192.168.20.80"],
            deviceType="Web Application Server",
            zone="DMZ",
            assetCriticality="HIGH",
            exposedPorts=[80, 443, 22],
            services=["HTTP", "HTTPS", "SSH"],
            vulnerabilities=["CVE-2026-WEB-RCE"],
            reachable=True
        ))

        self.add_node(AttackPathNode(
            nodeId="DB-01",
            deviceId="DB-01",
            nodeType=NodeTypeEnum.DATABASE,
            hostname="db-01.secure.internal",
            ipAddresses=["192.168.30.10"],
            deviceType="Production Database Server",
            zone="SECURE_DATA",
            assetCriticality="CRITICAL",
            exposedPorts=[3306],
            services=["MYSQL"],
            vulnerabilities=["CVE-2026-SQLI"],
            reachable=True
        ))

        self.add_node(AttackPathNode(
            nodeId="DNS-SERVER-01",
            deviceId="DNS-SERVER-01",
            nodeType=NodeTypeEnum.DNS_SERVER,
            hostname="dns-01.infra.internal",
            ipAddresses=["192.168.1.53"],
            deviceType="Internal DNS Server",
            zone="INFRA",
            assetCriticality="MEDIUM",
            exposedPorts=[53],
            services=["DNS"],
            reachable=True
        ))

        # 2. Register Directed Exploitation / Communication Edges
        # ATTACKER -> CLIENT-01 (Phishing / Web Ingress)
        self.add_edge(AttackPathEdge(
            edgeId="EDGE-ATT-CLIENT",
            sourceNode="ATTACKER-EXT",
            destinationNode="CLIENT-01",
            protocol="TCP",
            destinationPort=443,
            service="HTTPS",
            securityControl="EDGE-FIREWALL",
            reachable=True
        ))

        # CLIENT-01 -> WEB-01 (Internal Management / Pivot)
        self.add_edge(AttackPathEdge(
            edgeId="EDGE-CLIENT-WEB",
            sourceNode="CLIENT-01",
            destinationNode="WEB-01",
            protocol="TCP",
            destinationPort=22,
            service="SSH",
            securityControl="INTERNAL-SEGMENTATION-ACL",
            reachable=True
        ))

        # WEB-01 -> DB-01 (Application Data Tier Ingress)
        self.add_edge(AttackPathEdge(
            edgeId="EDGE-WEB-DB",
            sourceNode="WEB-01",
            destinationNode="DB-01",
            protocol="TCP",
            destinationPort=3306,
            service="MYSQL",
            securityControl="DMZ-TO-SECURE-FIREWALL",
            vulnerabilityExposure="CVE-2026-SQLI",
            reachable=True
        ))

        # CLIENT-01 -> DNS-SERVER-01 (Internal DNS queries)
        self.add_edge(AttackPathEdge(
            edgeId="EDGE-CLIENT-DNS",
            sourceNode="CLIENT-01",
            destinationNode="DNS-SERVER-01",
            protocol="UDP",
            destinationPort=53,
            service="DNS",
            reachable=True
        ))

    def add_node(self, node: AttackPathNode):
        if node.nodeId in self.nodes:
            raise ValueError(f"DUPLICATE_NODE: Node '{node.nodeId}' already exists in graph.")
        self.nodes[node.nodeId] = node
        if node.nodeId not in self.adjacency:
            self.adjacency[node.nodeId] = []

    def get_node(self, node_id: str) -> AttackPathNode:
        if not node_id or not node_id.strip():
            raise ValueError("nodeId cannot be empty.")
        clean_id = node_id.strip()
        if clean_id not in self.nodes:
            raise KeyError(f"UNKNOWN_DEVICE: Node '{clean_id}' is not in the attack graph.")
        return self.nodes[clean_id]

    def add_edge(self, edge: AttackPathEdge):
        if edge.sourceNode not in self.nodes:
            raise KeyError(f"INVALID_EDGE: Source node '{edge.sourceNode}' does not exist.")
        if edge.destinationNode not in self.nodes:
            raise KeyError(f"INVALID_EDGE: Destination node '{edge.destinationNode}' does not exist.")

        self.edges[edge.edgeId] = edge
        if edge.destinationNode not in self.adjacency[edge.sourceNode]:
            self.adjacency[edge.sourceNode].append(edge.destinationNode)

    def get_outgoing_edges(self, source_node: str) -> List[AttackPathEdge]:
        if source_node not in self.nodes:
            raise KeyError(f"UNKNOWN_DEVICE: Node '{source_node}' does not exist.")
        return [e for e in self.edges.values() if e.sourceNode == source_node]

    def has_directed_edge(self, source: str, destination: str) -> bool:
        if source not in self.nodes or destination not in self.nodes:
            return False
        return destination in self.adjacency.get(source, [])

    def build_path(
        self,
        attacker: str,
        entry_node: str,
        target_node: str,
        node_chain: List[str],
        status: PathStatusEnum = PathStatusEnum.POSSIBLE,
        risk_score: float = 0.0,
        risk_level: str = "LOW"
    ) -> AttackPath:
        # Validate that all nodes exist
        for nid in node_chain:
            if nid not in self.nodes:
                raise KeyError(f"UNKNOWN_DEVICE: Node '{nid}' in path chain does not exist.")

        # Find matching edges along the chain
        edge_ids = []
        vulns = []
        controls = []

        for i in range(len(node_chain) - 1):
            u, v = node_chain[i], node_chain[i + 1]
            matching = [e for e in self.edges.values() if e.sourceNode == u and e.destinationNode == v]
            if not matching:
                raise ValueError(f"DISCONNECTED_PATH: No directed edge exists between '{u}' and '{v}'.")
            edge = matching[0]
            edge_ids.append(edge.edgeId)
            if edge.vulnerabilityExposure:
                vulns.append(edge.vulnerabilityExposure)
            if edge.securityControl:
                controls.append(edge.securityControl)

        target_obj = self.get_node(target_node)
        vulns.extend(target_obj.vulnerabilities)

        return AttackPath(
            attacker=attacker,
            entryNode=entry_node,
            targetNode=target_node,
            nodes=node_chain,
            edges=edge_ids,
            pathLength=len(node_chain) - 1,
            pathStatus=status,
            reachability=status != PathStatusEnum.BLOCKED,
            pathRiskScore=risk_score,
            pathRiskLevel=risk_level,
            vulnerabilities=list(set(vulns)),
            securityControls=list(set(controls)),
            explanation=f"Identified {len(node_chain)-1}-hop traversal from {attacker} via {entry_node} to {target_node}."
        )

    def snapshot(self) -> Dict[str, Any]:
        data = {
            "nodeCount": len(self.nodes),
            "edgeCount": len(self.edges),
            "nodes": {k: v.model_dump() for k, v in self.nodes.items()},
            "edges": {k: v.model_dump() for k, v in self.edges.items()},
            "adjacency": self.adjacency
        }
        with open(GRAPH_SNAPSHOT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    def clear(self):
        self.nodes.clear()
        self.edges.clear()
        self.adjacency.clear()

attack_path_graph = AttackPathGraph()