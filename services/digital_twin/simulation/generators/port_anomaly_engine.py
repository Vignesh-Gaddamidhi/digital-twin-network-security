import random
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.port_anomaly import (
    PortAnomalyProfile, PortProbeMetric, PortAnomalyRunResult, PortStateMutationConfig
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)
from packages.shared_types.src.port_service_state import PortStateEnum
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.port_service_engine import port_service_engine

class PortAnomalyEngine:
    """Simulates unusual port access distributions, sweeps, and dynamic attack surface modifications."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random(881122)

    def _auto_provision(self, src: str, dst: str, baseline_ports: List[int]):
        from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
        if not device_registry.getDevice(src):
            device_registry.createDevice(NetworkDeviceModel(id=src, hostname=src.upper(), type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL))
        if not device_registry.getDevice(dst):
            device_registry.createDevice(NetworkDeviceModel(id=dst, hostname=dst.upper(), type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=baseline_ports))

    def runPortAnomalyScenario(
        self,
        profile: PortAnomalyProfile,
        simulation_id: str = "sim-portanom-01"
    ) -> PortAnomalyRunResult:
        self._auto_provision(profile.affectedDevice, profile.targetDevice, profile.baselinePorts)

        # 1. Check current listening ports on target
        active_ports = set()
        try:
            current_ports = port_service_engine.listPorts(profile.targetDevice)
            active_ports = {p.port for p in current_ports if p.state == PortStateEnum.OPEN}
        except Exception:
            pass

        target_dev = device_registry.getDevice(profile.targetDevice)
        if target_dev:
            active_ports.update(target_dev.ports)

        # 2. Simulate Port Attempts
        metrics_map: Dict[int, PortProbeMetric] = {}
        unusual_ports: List[int] = []
        total_attempts = 0

        for port in profile.probedPorts:
            attempts = profile.portAttemptWeights.get(port, 10)
            total_attempts += attempts
            is_open = port in active_ports

            if is_open:
                succ = attempts
                fail = 0
                state_str = "OPEN"
            else:
                succ = 0
                fail = attempts
                state_str = "CLOSED"

            if port not in profile.baselinePorts:
                unusual_ports.append(port)

            metrics_map[port] = PortProbeMetric(
                destinationPort=port,
                attemptCount=attempts,
                successfulConnections=succ,
                failedConnections=fail,
                portState=state_str
            )

        # 3. Dynamic Port State Mutation (e.g. 8080 -> OPEN)
        mutated = False
        mutation_details = None

        if profile.mutatePort:
            m = profile.mutatePort
            port_service_engine.openPort(
                device_id=profile.targetDevice,
                port_number=m.port,
                protocol="TCP",
                service_name=m.serviceName,
                reason=m.reason
            )
            mutated = True
            mutation_details = {
                "port": m.port,
                "state": m.newState,
                "service": m.serviceName,
                "reason": m.reason
            }
            # Update metrics record for this port
            if m.port in metrics_map:
                metrics_map[m.port].portState = "OPEN"
                metrics_map[m.port].successfulConnections = metrics_map[m.port].attemptCount
                metrics_map[m.port].failedConnections = 0

        return PortAnomalyRunResult(
            profileId=profile.profileId,
            targetDevice=profile.targetDevice,
            totalAttempts=total_attempts,
            portMetrics=list(metrics_map.values()),
            unusualPortsDetected=unusual_ports,
            stateMutated=mutated,
            mutatedPortDetails=mutation_details
        )

port_anomaly_engine = PortAnomalyEngine()