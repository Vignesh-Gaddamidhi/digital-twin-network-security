import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioCategoryEnum, AttackScenarioSeverityEnum,
    AttackScenarioStateEnum, ScenarioPrecondition, ScenarioTrafficPattern
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.simulation.attack.framework.scenario_state_machine import (
    AttackScenarioStateMachine, InvalidStateTransitionError
)
from services.digital_twin.simulation.attack.framework.scenario_validator import (
    ScenarioValidator, ScenarioPreconditionFailedError
)
from services.digital_twin.simulation.attack.framework.scenario_registry import (
    attack_scenario_registry, ScenarioAlreadyExistsError
)
from services.digital_twin.simulation.attack.scenarios.port_scan_scenario import PortScanAttackScenario

def run_attack_framework_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 65: ATTACK SCENARIO FRAMEWORK ARCHITECTURE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    port_service_engine.clear()
    attack_scenario_registry.clear()

    # 1. State Machine Invariants
    print("[1/5] Auditing State Machine Transitions & Invariant Rejections...")
    sm = AttackScenarioStateMachine(AttackScenarioStateEnum.CREATED)
    assert sm.current_state == AttackScenarioStateEnum.CREATED
    sm.transition_to(AttackScenarioStateEnum.VALIDATING)
    sm.transition_to(AttackScenarioStateEnum.READY)
    sm.transition_to(AttackScenarioStateEnum.RUNNING)
    sm.transition_to(AttackScenarioStateEnum.DETECTED)
    sm.transition_to(AttackScenarioStateEnum.RECOVERING)
    sm.transition_to(AttackScenarioStateEnum.COMPLETED)
    assert sm.current_state == AttackScenarioStateEnum.COMPLETED

    # Reject illegal transition (COMPLETED -> RUNNING)
    try:
        sm.transition_to(AttackScenarioStateEnum.RUNNING)
        assert False
    except InvalidStateTransitionError:
        print("    [PASS] Accurately rejected illegal leap from COMPLETED back to RUNNING.")

    # 2. Registry Management & ID Formatting
    print("\n[2/5] Auditing Attack Scenario Registry & ID Standards (SCN-*)...")
    runner = PortScanAttackScenario.create_canonical()
    attack_scenario_registry.register(runner.definition)
    assert len(attack_scenario_registry.listScenarios()) == 1
    assert attack_scenario_registry.get("SCN-PORTSCAN-001") is not None

    # Reject duplicate registration
    try:
        attack_scenario_registry.register(runner.definition)
        assert False
    except ScenarioAlreadyExistsError:
        print("    [PASS] Rejected duplicate scenario registration.")

    # 3. Precondition Validation (Target Missing)
    print("\n[3/5] Testing Precondition Validation Failures (Unprovisioned Target)...")
    try:
        runner.validate()
        assert False
    except ScenarioPreconditionFailedError:
        print("    [PASS] Precondition validator cleanly blocked execution on unprovisioned target.")

    # 4. Provision Topology and Satisfy Preconditions
    print("\n[4/5] Provisioning Topology to Satisfy Preconditions...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)

    # Fresh runner instance with provisioned environment
    runner = PortScanAttackScenario.create_canonical()

    # Validating should now succeed
    assert runner.validate() is True
    assert runner.state_machine.current_state == AttackScenarioStateEnum.READY
    print("    [PASS] Preconditions satisfied: Target is online with ports 80 and 443 OPEN.")

    # 5. Full End-to-End Scenario Run & Indicator Detection
    print("\n[5/5] Executing Full Scenario Lifecycle (READY -> RUNNING -> DETECTED -> RECOVERING -> COMPLETED)...")
    exec_status = runner.run()

    print(f"    Final Execution State : {exec_status.currentState.value}")
    print(f"    Indicators Manifested : {exec_status.indicatorsObserved}")
    assert exec_status.currentState == AttackScenarioStateEnum.COMPLETED
    assert "PORT_SPREAD_ANOMALY" in exec_status.indicatorsObserved
    print("    [PASS] Canonical SCN-PORTSCAN-001 executed cleanly and manifested PORT_SPREAD_ANOMALY.")

    print("\n" + "=" * 80)
    print("       ALL DAY 65 ATTACK SCENARIO FRAMEWORK TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_attack_framework_suite()