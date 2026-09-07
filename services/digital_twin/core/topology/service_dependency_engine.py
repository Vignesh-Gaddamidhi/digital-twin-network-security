from typing import Dict, List, Optional, Set
import networkx as nx
from packages.shared_types.src.service_dependency import (
    ServiceDependencyModel, ServiceDependencyChainResult, DependencyTypeEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class ServiceDependencyEngine:
    """Manages application-level dependencies between clients and multi-tier server daemons."""

    def __init__(self):
        self._dependencies: Dict[str, ServiceDependencyModel] = {}
        self._dependency_graph: nx.DiGraph = nx.DiGraph()

    def registerDependency(self, dep: ServiceDependencyModel) -> ServiceDependencyModel:
        # Validate endpoints exist
        src = device_registry.getDevice(dep.source_device_id)
        if not src:
            raise DeviceNotFoundError(f"Source device '{dep.source_device_id}' not found.")
        dst = device_registry.getDevice(dep.target_device_id)
        if not dst:
            raise DeviceNotFoundError(f"Target device '{dep.target_device_id}' not found.")

        # Ensure target device actually listens on the requested port
        if dep.target_port not in dst.ports:
            raise ValueError(f"Target device '{dst.hostname}' does not have port {dep.target_port} configured.")

        self._dependencies[dep.id] = dep
        self._dependency_graph.add_edge(
            dep.source_device_id,
            dep.target_device_id,
            dep_id=dep.id,
            service=dep.target_service_name,
            port=dep.target_port,
            protocol=dep.protocol,
            dep_type=dep.dependency_type.value
        )
        return dep

    def getDependenciesForDevice(self, device_id: str) -> List[ServiceDependencyModel]:
        return [d for d in self._dependencies.values() if d.source_device_id == device_id or d.target_device_id == device_id]

    def listAllDependencies(self) -> List[ServiceDependencyModel]:
        return list(self._dependencies.values())

    def traceDependencyChain(self, source_device_id: str, target_device_id: str) -> ServiceDependencyChainResult:
        """Determines whether a client or service depends on an upstream service directly or transitively."""
        if source_device_id not in self._dependency_graph or target_device_id not in self._dependency_graph:
            return ServiceDependencyChainResult(
                root_client_id=source_device_id,
                target_service_id=target_device_id,
                dependency_chain=[],
                total_depth=0,
                direct_dependency=False,
                explanation=f"No dependency path exists between '{source_device_id}' and '{target_device_id}'."
            )

        try:
            path = nx.shortest_path(self._dependency_graph, source=source_device_id, target=target_device_id)
            is_direct = len(path) == 2
            readable_names = [device_registry.getDevice(d).hostname if device_registry.getDevice(d) else d for d in path]
            return ServiceDependencyChainResult(
                root_client_id=source_device_id,
                target_service_id=target_device_id,
                dependency_chain=readable_names,
                total_depth=len(path) - 1,
                direct_dependency=is_direct,
                explanation=f"{'Direct' if is_direct else 'Transitive multi-tier'} dependency chain: {' -> '.join(readable_names)}."
            )
        except nx.NetworkXNoPath:
            return ServiceDependencyChainResult(
                root_client_id=source_device_id,
                target_service_id=target_device_id,
                dependency_chain=[],
                total_depth=0,
                direct_dependency=False,
                explanation=f"Target service '{target_device_id}' is not reachable in the dependency graph from '{source_device_id}'."
            )

    def clear(self):
        self._dependencies.clear()
        self._dependency_graph.clear()

service_dependency_engine = ServiceDependencyEngine()