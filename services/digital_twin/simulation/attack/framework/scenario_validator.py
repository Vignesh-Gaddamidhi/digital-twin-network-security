from typing import Tuple, List
from packages.shared_types.src.attack_scenario import AttackScenarioModel
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.port_service_engine import port_service_engine
from packages.shared_types.src.port_service_state import PortStateEnum

class ScenarioPreconditionFailedError(ValueError):
    pass

class ScenarioValidator:
    """Validates structural constraints and digital twin preconditions for an attack scenario."""

    @staticmethod
    def validate_preconditions(scenario: AttackScenarioModel) -> Tuple[bool, List[str]]:
        failures = []
        pre = scenario.preconditions

        # 1. Source device exists
        if not device_registry.getDevice(scenario.sourceDevice):
            failures.append(f"Source device '{scenario.sourceDevice}' is not registered.")

        # 2. Target device exists
        tgt = device_registry.getDevice(pre.targetDevice)
        if not tgt:
            failures.append(f"Target device '{pre.targetDevice}' is not registered.")
            return False, failures

        # 3. Check Required Open Ports
        if pre.requiredOpenPorts:
            open_ports = set(tgt.ports)
            try:
                live_ports = port_service_engine.listPorts(pre.targetDevice)
                open_ports.update(p.port for p in live_ports if p.state == PortStateEnum.OPEN)
            except Exception:
                pass
            
            missing_open = set(pre.requiredOpenPorts) - open_ports
            if missing_open:
                failures.append(f"Target '{pre.targetDevice}' missing required OPEN ports: {list(missing_open)}")

        # 4. Check Required Closed Ports
        if pre.requiredClosedPorts:
            open_ports = set(tgt.ports)
            conflict_ports = set(pre.requiredClosedPorts).intersection(open_ports)
            if conflict_ports:
                failures.append(f"Target '{pre.targetDevice}' has ports that must be CLOSED: {list(conflict_ports)}")

        return (len(failures) == 0), failures