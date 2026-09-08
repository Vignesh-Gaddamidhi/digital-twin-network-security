from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from packages.shared_types.src.complete_graph import (
    CompleteDigitalTwinGraphModel, CompleteGraphSummary
)
from packages.shared_types.src.network_device import NetworkDeviceModel
from packages.shared_types.src.topology import NetworkConnectionModel
from packages.shared_types.src.zone_graph import ZoneDefinitionModel
from packages.shared_types.src.service_graph import DetailedServiceDependencyModel
from packages.shared_types.src.firewall import FirewallRuleModel

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.zone_engine import zone_engine
from services.digital_twin.core.topology.service_graph_engine import service_graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.topology.graph_engine import graph_engine
from packages.shared_types.src.graph import GraphNodeModel, GraphEdgeModel

class CompleteGraphEngine:
    """Master synthesizer consolidating physical, logical, security, and application layers."""

    @staticmethod
    def synchronizeUnderlyingGraph():
        """Ensures the NetworkX mathematical graph engine reflects all devices and connections."""
        graph_engine.clear()

        for dev in device_registry.getAllDevices():
            zone = zone_engine.getDeviceZone(dev.id) or (dev.networkZone.value if hasattr(dev.networkZone, "value") else str(dev.networkZone))
            graph_engine.addNode(GraphNodeModel(
                id=dev.id,
                type=dev.type.value if hasattr(dev.type, "value") else str(dev.type),
                label=dev.hostname,
                zone=zone,
                state=dev.currentState,
                metadata={"riskScore": dev.riskScore, "securityState": dev.securityState}
            ))

        for conn in connection_registry.getAllConnections():
            graph_engine.addEdge(GraphEdgeModel(
                id=conn.id,
                source=conn.sourceDevice,
                target=conn.destinationDevice,
                protocol=conn.protocol.value if hasattr(conn.protocol, "value") else str(conn.protocol),
                status=conn.status.value if hasattr(conn.status, "value") else str(conn.status),
                weight=conn.latency,
                metadata={"bandwidth": conn.bandwidth, "port": conn.destinationPort}
            ), is_bidirectional=True)

    @classmethod
    def getCompleteDigitalTwinGraph(cls, graph_id: str = "DT-CANONICAL-V1") -> CompleteDigitalTwinGraphModel:
        cls.synchronizeUnderlyingGraph()

        devices = device_registry.getAllDevices()
        connections = connection_registry.getAllConnections()
        zones = zone_engine.listZones()
        deps = service_graph_engine.listDependencies()
        rules = firewall_engine.listRules()

        active_devs = sum(1 for d in devices if d.currentState == "ONLINE")
        compromised_devs = sum(1 for d in devices if d.securityState == "COMPROMISED")

        total_lat = sum(c.latency for c in connections)
        avg_lat = round(total_lat / len(connections), 2) if connections else 0.0

        summary = CompleteGraphSummary(
            total_devices=len(devices),
            total_connections=len(connections),
            total_zones=len(zones),
            total_dependencies=len(deps),
            total_firewall_rules=len(rules),
            active_devices_count=active_devs,
            compromised_devices_count=compromised_devs,
            average_latency_ms=avg_lat
        )

        return CompleteDigitalTwinGraphModel(
            graph_id=graph_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            devices=devices,
            connections=connections,
            zones=zones,
            dependencies=deps,
            firewall_rules=rules,
            metadata={
                "graph_engine_nodes": len(graph_engine._nodes),
                "graph_engine_edges": len(graph_engine._edges)
            }
        )

    @classmethod
    def generateDay42Snapshot(cls) -> Dict[str, Any]:
        cls.synchronizeUnderlyingGraph()
        devices = device_registry.getAllDevices()
        connections = connection_registry.getAllConnections()
        zones = zone_engine.listZones()

        dev_items = [
            {
                "id": d.id,
                "type": d.type.value if hasattr(d.type, "value") else str(d.type),
                "zone": zone_engine.getDeviceZone(d.id) or (d.networkZone.value if hasattr(d.networkZone, "value") else str(d.networkZone)),
                "state": d.currentState
            }
            for d in devices
        ]

        inet_dev = next((d for d in devices if "inet" in d.id.lower() or (hasattr(d.networkZone, "value") and d.networkZone.value == "EXTERNAL")), None)
        web_dev = next((d for d in devices if "web" in d.id.lower()), None)

        is_reachable = False
        if inet_dev and web_dev:
            from services.digital_twin.core.topology.reachability_engine import reachability_engine
            res = reachability_engine.isReachable(inet_dev.id, web_dev.id, protocol="TCP", destination_port=443)
            is_reachable = res.is_reachable

        return {
            "network": {
                "devices": len(devices),
                "connections": len(connections),
                "zones": len(zones)
            },
            "devices": dev_items,
            "topology": {
                "reachable": is_reachable
            }
        }

complete_graph_engine = CompleteGraphEngine()