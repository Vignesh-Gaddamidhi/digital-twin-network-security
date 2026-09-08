from typing import Dict, List, Optional, Set
import networkx as nx

from packages.shared_types.src.service_graph import (
    DetailedServiceDependencyModel, ImpactPropagationResult, 
    ImpactedServiceNode, ServiceCriticalityEnum, ServiceDependencyStatusEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class ServiceGraphEngine:
    """Manages Layer 7 service-to-service relationships and evaluates impact propagation."""

    def __init__(self):
        self._dependencies: Dict[str, DetailedServiceDependencyModel] = {}
        # Directed graph: edge (source_endpoint) -> (dest_endpoint)
        # Note: If A depends on B, edge is A -> B.
        # Upstream impact flows in reverse: B fails -> affects A.
        self._graph: nx.DiGraph = nx.DiGraph()

    def _make_node_key(self, device_id: str, service_name: str) -> str:
        return f"{device_id}::{service_name}"

    def addDependency(self, dep: DetailedServiceDependencyModel) -> DetailedServiceDependencyModel:
        # Validate devices exist
        src = device_registry.getDevice(dep.sourceDevice)
        if not src:
            raise DeviceNotFoundError(f"Source device '{dep.sourceDevice}' not found.")
        dst = device_registry.getDevice(dep.destinationDevice)
        if not dst:
            raise DeviceNotFoundError(f"Destination device '{dep.destinationDevice}' not found.")

        # Ensure destination device has port configured
        if dep.port not in dst.ports:
            raise ValueError(f"Port {dep.port} is not listening on destination device '{dst.hostname}'.")

        src_key = self._make_node_key(dep.sourceDevice, dep.sourceService)
        dst_key = self._make_node_key(dep.destinationDevice, dep.destinationService)

        self._dependencies[dep.id] = dep
        self._graph.add_edge(
            src_key,
            dst_key,
            id=dep.id,
            protocol=dep.protocol,
            port=dep.port,
            status=dep.status.value,
            criticality=dep.criticality.value
        )
        return dep

    def removeDependency(self, dependency_id: str) -> bool:
        if dependency_id not in self._dependencies:
            raise KeyError(f"Dependency '{dependency_id}' not found.")
        dep = self._dependencies[dependency_id]
        src_key = self._make_node_key(dep.sourceDevice, dep.sourceService)
        dst_key = self._make_node_key(dep.destinationDevice, dep.destinationService)

        if self._graph.has_edge(src_key, dst_key):
            self._graph.remove_edge(src_key, dst_key)
        del self._dependencies[dependency_id]
        return True

    def listDependencies(self, device_id: Optional[str] = None) -> List[DetailedServiceDependencyModel]:
        deps = list(self._dependencies.values())
        if device_id:
            deps = [d for d in deps if d.sourceDevice == device_id or d.destinationDevice == device_id]
        return deps

    def propagateImpact(self, failed_device_id: str, failed_service_name: str) -> ImpactPropagationResult:
        """Traces the upstream blast radius when a critical backend service or database fails."""
        root_key = self._make_node_key(failed_device_id, failed_service_name)
        if root_key not in self._graph:
            # If no dependencies registered for this exact key, return empty impact
            return ImpactPropagationResult(
                failed_device_id=failed_device_id,
                failed_service=failed_service_name,
                total_impacted_services=0,
                total_impacted_devices=0,
                blast_radius_score=0.0,
                impacted_services=[],
                propagation_chain=[root_key]
            )

        # Reverse the directed graph: edges now point from provider to consumer
        reversed_graph = self._graph.reverse()

        # Find all nodes reachable from root_key in the reversed graph (consumers)
        impacted_keys = nx.descendants(reversed_graph, root_key)

        impacted_nodes: List[ImpactedServiceNode] = []
        impacted_device_ids: Set[str] = set()
        propagation_chain = [root_key]

        criticality_weights = {
            "CRITICAL": 10.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 1.0
        }
        total_weight = 0.0

        for key in impacted_keys:
            dev_id, srv_name = key.split("::")
            impacted_device_ids.add(dev_id)
            dev = device_registry.getDevice(dev_id)
            hostname = dev.hostname if dev else dev_id

            # Compute shortest path distance from root to this consumer in reversed graph
            depth = nx.shortest_path_length(reversed_graph, source=root_key, target=key)
            is_direct = (depth == 1)

            # Determine impact criticality based on the incident edge
            edge_data = reversed_graph.get_edge_data(root_key, key) or {}
            crit = edge_data.get("criticality", "HIGH")
            total_weight += criticality_weights.get(crit, 5.0)

            impacted_nodes.append(ImpactedServiceNode(
                device_id=dev_id,
                hostname=hostname,
                service_name=srv_name,
                impact_level=crit,
                dependency_depth=depth,
                direct_dependency=is_direct
            ))
            propagation_chain.append(key)

        # Sort by dependency depth ascending (direct consumers first)
        impacted_nodes.sort(key=lambda x: x.dependency_depth)

        blast_radius = min(round(total_weight * 2.5, 2), 100.0)

        return ImpactPropagationResult(
            failed_device_id=failed_device_id,
            failed_service=failed_service_name,
            total_impacted_services=len(impacted_nodes),
            total_impacted_devices=len(impacted_device_ids),
            blast_radius_score=blast_radius,
            impacted_services=impacted_nodes,
            propagation_chain=propagation_chain
        )

    def clear(self):
        self._dependencies.clear()
        self._graph.clear()

service_graph_engine = ServiceGraphEngine()