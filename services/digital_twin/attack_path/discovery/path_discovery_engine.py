import json
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

ROOT_DIR = Path(__file__).resolve().parents[4]
DISCOVERY_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
DISCOVERIES_FILE = DISCOVERY_ARTIFACTS_DIR / "path_discoveries.json"

from services.digital_twin.attack_path.graph.graph_models import (
    PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.discovery.discovery_models import (
    TraversalMethodEnum, PathConstraints, DiscoveredPathDetail, PathDiscoveryResult
)

class PathDiscoveryEngine:
    """Explores directed security-aware paths, evaluating reachability, firewalls, and bottlenecks."""

    def __init__(self, artifacts_dir: Path = DISCOVERY_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.history: List[PathDiscoveryResult] = []

    def _evaluate_path_reachability(
        self,
        node_chain: List[str],
        constraints: PathConstraints
    ) -> Tuple[PathStatusEnum, Optional[str], Optional[str], List[str], List[str], List[str]]:
        edge_ids = []
        vulns = []
        controls = []
        blocked_at = None
        blocking_reason = None
        status = PathStatusEnum.POSSIBLE

        for i in range(len(node_chain) - 1):
            u_id = node_chain[i]
            v_id = node_chain[i + 1]

            u_node = attack_path_graph.get_node(u_id)
            v_node = attack_path_graph.get_node(v_id)

            # 1. Node Isolation Check
            if u_node.securityState == "QUARANTINED" or u_node.securityState == "ISOLATED":
                return PathStatusEnum.BLOCKED, v_id, f"Source node '{u_id}' is isolated/quarantined.", edge_ids, vulns, controls

            if v_node.securityState == "QUARANTINED" or v_node.securityState == "ISOLATED":
                return PathStatusEnum.BLOCKED, v_id, f"Node '{v_id}' is isolated/quarantined.", edge_ids, vulns, controls

            # 2. Zone Constraint Filter
            if constraints.blockedZones and (v_node.zone in constraints.blockedZones or u_node.zone in constraints.blockedZones):
                return PathStatusEnum.BLOCKED, v_id, f"Zone '{v_node.zone}' is explicitly blocked by constraints.", edge_ids, vulns, controls

            # 3. Find matching directed edge
            matching = [e for e in attack_path_graph.edges.values() if e.sourceNode == u_id and e.destinationNode == v_id]
            if not matching:
                return PathStatusEnum.BLOCKED, v_id, f"No edge between '{u_id}' and '{v_id}'.", edge_ids, vulns, controls

            edge = matching[0]
            edge_ids.append(edge.edgeId)
            if edge.vulnerabilityExposure:
                vulns.append(edge.vulnerabilityExposure)
            if edge.securityControl:
                controls.append(edge.securityControl)

            # Protocol Constraint Filter
            if constraints.allowedProtocols and edge.protocol.upper() not in [p.upper() for p in constraints.allowedProtocols]:
                return PathStatusEnum.BLOCKED, v_id, f"Protocol '{edge.protocol}' not permitted by constraints.", edge_ids, vulns, controls

            # Edge Reachability & Security Control Filter
            if not edge.reachable or edge.status == "BLOCKED":
                blocked_at = v_id
                blocking_reason = edge.securityControl or "Edge marked BLOCKED by security policy."
                if i == 0:
                    status = PathStatusEnum.BLOCKED
                else:
                    status = PathStatusEnum.PARTIALLY_REACHABLE
                break

        # Collect target vulnerabilities
        tgt_node = attack_path_graph.get_node(node_chain[-1])
        vulns.extend(tgt_node.vulnerabilities)

        return status, blocked_at, blocking_reason, edge_ids, list(set(vulns)), list(set(controls))

    def find_shortest_path(
        self,
        source: str,
        target: str,
        constraints: Optional[PathConstraints] = None,
        only_reachable: bool = False,
        persist: bool = True
    ) -> PathDiscoveryResult:
        c = constraints or PathConstraints()
        # Verify endpoints exist
        _ = attack_path_graph.get_node(source)
        _ = attack_path_graph.get_node(target)

        queue = deque([[source]])
        visited_nodes: Set[str] = {source}
        found_chain = None

        while queue:
            curr_path = queue.popleft()
            curr_node = curr_path[-1]

            if curr_node == target and len(curr_path) > 1:
                # If only_reachable is requested, verify path validity before accepting
                if only_reachable:
                    st, _, _, _, _, _ = self._evaluate_path_reachability(curr_path, c)
                    if st == PathStatusEnum.POSSIBLE:
                        found_chain = curr_path
                        break
                else:
                    found_chain = curr_path
                    break

            if len(curr_path) > c.maxDepth:
                continue

            for neighbor in attack_path_graph.adjacency.get(curr_node, []):
                if neighbor not in visited_nodes:
                    if only_reachable:
                        # Check edge reachability
                        matching = [e for e in attack_path_graph.edges.values() if e.sourceNode == curr_node and e.destinationNode == neighbor]
                        if not matching or not matching[0].reachable or matching[0].status == "BLOCKED":
                            continue
                    visited_nodes.add(neighbor)
                    queue.append(curr_path + [neighbor])

        discovered_paths = []
        if found_chain:
            status, blk_at, blk_rsn, edges, vulns, ctrls = self._evaluate_path_reachability(found_chain, c)
            discovered_paths.append(DiscoveredPathDetail(
                nodeSequence=found_chain,
                edgeSequence=edges,
                hopCount=len(found_chain) - 1,
                status=status,
                blockedAt=blk_at,
                blockingReason=blk_rsn,
                vulnerabilitiesEncountered=vulns,
                securityControlsEncountered=ctrls
            ))

        pos_count = sum(1 for p in discovered_paths if p.status == PathStatusEnum.POSSIBLE)
        blk_count = sum(1 for p in discovered_paths if p.status == PathStatusEnum.BLOCKED)
        prt_count = sum(1 for p in discovered_paths if p.status == PathStatusEnum.PARTIALLY_REACHABLE)

        result = PathDiscoveryResult(
            source=source,
            target=target,
            traversalMethod=TraversalMethodEnum.BFS_SHORTEST,
            pathsFound=len(discovered_paths),
            pathsPossible=pos_count,
            pathsBlocked=blk_count,
            pathsPartial=prt_count,
            maximumDepth=c.maxDepth,
            paths=discovered_paths
        )

        self.history.append(result)
        if persist:
            self._persist_result(result)
        return result

    def find_all_paths(
        self,
        source: str,
        target: str,
        constraints: Optional[PathConstraints] = None,
        persist: bool = True
    ) -> PathDiscoveryResult:
        c = constraints or PathConstraints()
        _ = attack_path_graph.get_node(source)
        _ = attack_path_graph.get_node(target)

        discovered_details: List[DiscoveredPathDetail] = []
        visited_in_path: Set[str] = set()

        def dfs(curr_node: str, current_chain: List[str]):
            if len(discovered_details) >= c.maxPaths:
                return
            if len(current_chain) > c.maxDepth + 1:
                return

            if curr_node == target and len(current_chain) > 1:
                status, blk_at, blk_rsn, edges, vulns, ctrls = self._evaluate_path_reachability(current_chain, c)
                discovered_details.append(DiscoveredPathDetail(
                    nodeSequence=list(current_chain),
                    edgeSequence=edges,
                    hopCount=len(current_chain) - 1,
                    status=status,
                    blockedAt=blk_at,
                    blockingReason=blk_rsn,
                    vulnerabilitiesEncountered=vulns,
                    securityControlsEncountered=ctrls
                ))
                return

            visited_in_path.add(curr_node)

            for neighbor in attack_path_graph.adjacency.get(curr_node, []):
                # Cycle prevention: Do not revisit node currently on active branch
                if neighbor not in visited_in_path:
                    dfs(neighbor, current_chain + [neighbor])

            visited_in_path.remove(curr_node)

        dfs(source, [source])

        pos_count = sum(1 for p in discovered_details if p.status == PathStatusEnum.POSSIBLE)
        blk_count = sum(1 for p in discovered_details if p.status == PathStatusEnum.BLOCKED)
        prt_count = sum(1 for p in discovered_details if p.status == PathStatusEnum.PARTIALLY_REACHABLE)

        result = PathDiscoveryResult(
            source=source,
            target=target,
            traversalMethod=TraversalMethodEnum.DFS_ALL_BOUNDED,
            pathsFound=len(discovered_details),
            pathsPossible=pos_count,
            pathsBlocked=blk_count,
            pathsPartial=prt_count,
            maximumDepth=c.maxDepth,
            paths=discovered_details
        )

        self.history.append(result)
        if persist:
            self._persist_result(result)
        return result

    def _persist_result(self, res: PathDiscoveryResult):
        existing = []
        if DISCOVERIES_FILE.exists():
            try:
                with open(DISCOVERIES_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(res.model_dump())
        existing = existing[-100:]
        with open(DISCOVERIES_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        if DISCOVERIES_FILE.exists():
            try:
                DISCOVERIES_FILE.unlink()
            except Exception:
                pass

path_discovery_engine = PathDiscoveryEngine()