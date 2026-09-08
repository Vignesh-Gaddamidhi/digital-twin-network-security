import ipaddress
from typing import Dict, List, Optional, Tuple, Any
from packages.shared_types.src.network_device import (
    NetworkDeviceModel, RouteEntryModel, RouteStatusEnum, 
    ForwardingDecisionResult, DeviceTypeEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class RoutingEngine:
    """Manages routing tables and calculates Layer 3 Longest-Prefix Matching forwarding decisions."""

    @staticmethod
    def addRoute(router_id: str, route: RouteEntryModel) -> RouteEntryModel:
        router = device_registry.getDevice(router_id)
        if not router:
            raise DeviceNotFoundError(f"Router '{router_id}' not found.")
        if router.type not in (DeviceTypeEnum.ROUTER, DeviceTypeEnum.FIREWALL):
            raise ValueError(f"Device '{router_id}' is of type '{router.type.value}', not a ROUTER or FIREWALL.")

        # Remove duplicate destination prefix if present
        router.routes = [r for r in router.routes if r.destination != route.destination]
        router.routes.append(route)
        device_registry.updateDevice(router)
        return route

    @staticmethod
    def removeRoute(router_id: str, destination_cidr: str) -> bool:
        router = device_registry.getDevice(router_id)
        if not router:
            raise DeviceNotFoundError(f"Router '{router_id}' not found.")

        initial_len = len(router.routes)
        router.routes = [r for r in router.routes if r.destination != destination_cidr]
        if len(router.routes) == initial_len:
            raise ValueError(f"Route to '{destination_cidr}' not found on router '{router_id}'.")

        device_registry.updateDevice(router)
        return True

    @staticmethod
    def getRoutingTable(router_id: str) -> List[RouteEntryModel]:
        router = device_registry.getDevice(router_id)
        if not router:
            raise DeviceNotFoundError(f"Router '{router_id}' not found.")
        return [r for r in router.routes if r.status == RouteStatusEnum.ACTIVE]

    @classmethod
    def findRoute(cls, router_id: str, destination_ip: str) -> ForwardingDecisionResult:
        """Applies Longest-Prefix Match (LPM) to find the best route for a given destination IP."""
        target_ip = ipaddress.ip_address(destination_ip)
        routes = cls.getRoutingTable(router_id)

        matching_routes: List[Tuple[ipaddress.IPv4Network, RouteEntryModel]] = []

        for r in routes:
            net = ipaddress.ip_network(r.destination, strict=False)
            if target_ip in net:
                matching_routes.append((net, r))

        if not matching_routes:
            return ForwardingDecisionResult(
                destination_ip=destination_ip,
                next_hop="UNREACHABLE",
                egress_interface="NONE",
                is_direct=False,
                path_resolved=False,
                explanation=f"No matching route found in routing table of '{router_id}' for {destination_ip}."
            )

        # Sort matches: highest prefix length first, then lowest metric
        matching_routes.sort(key=lambda x: (x[0].prefixlen, -x[1].metric), reverse=True)
        best_net, best_route = matching_routes[0]

        is_direct = best_route.nextHop is None or best_route.nextHop.upper() == "DIRECT"
        next_hop = destination_ip if is_direct else best_route.nextHop

        return ForwardingDecisionResult(
            destination_ip=destination_ip,
            matched_route=best_route,
            next_hop=next_hop,
            egress_interface=best_route.interface,
            is_direct=is_direct,
            path_resolved=True,
            explanation=f"Matched prefix {best_net} (length /{best_net.prefixlen}) via interface {best_route.interface}."
        )

    @classmethod
    def traceLayer3Path(cls, source_device_id: str, destination_ip: str, max_hops: int = 10) -> List[Dict[str, Any]]:
        """Simulates Layer 3 forwarding hop-by-hop from a host through intermediate routers."""
        trace = []
        current_node_id = source_device_id
        visited = set()

        for hop_index in range(max_hops):
            current_dev = device_registry.getDevice(current_node_id)
            if not current_dev:
                break

            visited.add(current_node_id)

            # If current node is the destination
            if any(iface.ip_address == destination_ip for iface in current_dev.interfaces) or destination_ip in current_dev.ipAddresses:
                trace.append({
                    "hop": hop_index + 1,
                    "device_id": current_node_id,
                    "hostname": current_dev.hostname,
                    "action": "DESTINATION_REACHED",
                    "ip": destination_ip
                })
                break

            # If node is a host, forward to its default gateway
            if current_dev.type not in (DeviceTypeEnum.ROUTER, DeviceTypeEnum.FIREWALL):
                # Find connected gateway
                gateway_ip = None
                for iface in current_dev.interfaces:
                    if iface.subnet_cidr:
                        net = ipaddress.ip_network(iface.subnet_cidr, strict=False)
                        if ipaddress.ip_address(destination_ip) in net:
                            # Direct L2 delivery
                            trace.append({
                                "hop": hop_index + 1,
                                "device_id": current_node_id,
                                "hostname": current_dev.hostname,
                                "action": "DIRECT_LAN_DELIVERY",
                                "target_ip": destination_ip
                            })
                            return trace

                # Need default router - lookup router on LAN
                router = next((d for d in device_registry.getAllDevices() if d.type == DeviceTypeEnum.ROUTER), None)
                if not router:
                    trace.append({"hop": hop_index + 1, "device_id": current_node_id, "action": "NO_GATEWAY_CONFIGURED"})
                    break

                trace.append({
                    "hop": hop_index + 1,
                    "device_id": current_node_id,
                    "hostname": current_dev.hostname,
                    "action": "FORWARD_TO_DEFAULT_GATEWAY",
                    "gateway_id": router.id
                })
                current_node_id = router.id
                continue

            # Node is a ROUTER: evaluate LPM
            decision = cls.findRoute(current_node_id, destination_ip)
            if not decision.path_resolved:
                trace.append({
                    "hop": hop_index + 1,
                    "device_id": current_node_id,
                    "hostname": current_dev.hostname,
                    "action": "PACKET_DROPPED_NO_ROUTE",
                    "explanation": decision.explanation
                })
                break

            trace.append({
                "hop": hop_index + 1,
                "device_id": current_node_id,
                "hostname": current_dev.hostname,
                "action": "L3_FORWARD",
                "matched_prefix": decision.matched_route.destination,
                "next_hop": decision.next_hop,
                "egress_interface": decision.egress_interface,
                "is_direct": decision.is_direct
            })

            if decision.is_direct:
                trace.append({
                    "hop": hop_index + 2,
                    "device_id": "DESTINATION",
                    "action": "DELIVERED_TO_TARGET",
                    "ip": destination_ip
                })
                break

            # Find next hop router device
            next_hop_dev = next((d for d in device_registry.getAllDevices() if decision.next_hop in d.ipAddresses), None)
            if not next_hop_dev or next_hop_dev.id in visited:
                break
            current_node_id = next_hop_dev.id

        return trace

routing_engine = RoutingEngine()