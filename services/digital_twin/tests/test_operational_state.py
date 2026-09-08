import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.device_state import OperationalStatusEnum, SecurityPostureEnum
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.state_transition_engine import (
    state_transition_engine, InvalidStateTransitionError
)

def run_operational_state_suite():
    print("=" * 80)
    print("       WEEK 7 - DAY 44: DEVICE OPERATIONAL STATE TRANSITION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    state_transition_engine.clear()

    # 1. Setup Base Device
    print("[1/5] Provisioning Base Server (web-01) in Device Registry...")
    web = NetworkDeviceModel(
        id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DMZ, currentState="ACTIVE"
    )
    device_registry.createDevice(web)
    assert state_transition_engine.getCurrentState("web-01") == OperationalStatusEnum.ACTIVE
    print("    [PASS] Device 'web-01' provisioned in ACTIVE operational state.")

    # 2. Sequential Valid Transitions
    print("\n[2/5] Testing Sequential State Transitions...")

    # Transition A: ACTIVE -> DEGRADED (PASS)
    rec_a = state_transition_engine.transitionState(
        "web-01", OperationalStatusEnum.DEGRADED, reason="CPU reached 95%", trigger="TELEMETRY"
    )
    assert rec_a.fromState == OperationalStatusEnum.ACTIVE
    assert rec_a.toState == OperationalStatusEnum.DEGRADED
    assert state_transition_engine.getCurrentState("web-01") == OperationalStatusEnum.DEGRADED
    print(f"    [PASS] ACTIVE -> DEGRADED: Reason: '{rec_a.reason}'")

    # Transition B: DEGRADED -> OFFLINE (PASS)
    rec_b = state_transition_engine.transitionState(
        "web-01", OperationalStatusEnum.OFFLINE, reason="Nginx web service failure", trigger="HEALTH_CHECK"
    )
    assert rec_b.fromState == OperationalStatusEnum.DEGRADED
    assert rec_b.toState == OperationalStatusEnum.OFFLINE
    assert state_transition_engine.getCurrentState("web-01") == OperationalStatusEnum.OFFLINE
    print(f"    [PASS] DEGRADED -> OFFLINE: Reason: '{rec_b.reason}'")

    # Transition C: OFFLINE -> ACTIVE (PASS)
    rec_c = state_transition_engine.transitionState(
        "web-01", OperationalStatusEnum.ACTIVE, reason="Server reboot and health recovery", trigger="RESTART"
    )
    assert rec_c.fromState == OperationalStatusEnum.OFFLINE
    assert rec_c.toState == OperationalStatusEnum.ACTIVE
    assert state_transition_engine.getCurrentState("web-01") == OperationalStatusEnum.ACTIVE
    print(f"    [PASS] OFFLINE -> ACTIVE: Reason: '{rec_c.reason}'")

    # 3. Invalid Transition Rejection
    print("\n[3/5] Testing Rejection of Illegal Transitions...")
    # Set to STARTING first
    web2 = NetworkDeviceModel(id="web-02", hostname="WEB-02", type=DeviceTypeEnum.SERVER, currentState="STARTING")
    device_registry.createDevice(web2)

    # Illegal transition: STARTING cannot jump directly to ISOLATED
    assert state_transition_engine.canTransition("web-02", OperationalStatusEnum.ISOLATED) is False
    try:
        state_transition_engine.transitionState("web-02", OperationalStatusEnum.ISOLATED)
        assert False, "Failed to reject illegal transition!"
    except InvalidStateTransitionError as e:
        print(f"    [PASS] Safely rejected invalid transition: {e}")

    # 4. Unknown Device Handling
    print("\n[4/5] Testing Unknown Device Rejection...")
    try:
        state_transition_engine.transitionState("ghost-server", OperationalStatusEnum.ACTIVE)
        assert False, "Failed to reject unknown device!"
    except DeviceNotFoundError as e:
        print(f"    [PASS] Safely rejected unknown device: {e}")

    # 5. Independence of Operational vs. Security State
    print("\n[5/5] Testing Orthogonality of Operational and Security States...")
    # web-01 is ACTIVE operationally, but we can flag it as COMPROMISED from a security perspective
    web_dev = device_registry.getDevice("web-01")
    web_dev.securityState = SecurityPostureEnum.COMPROMISED.value
    device_registry.updateDevice(web_dev)

    assert state_transition_engine.getCurrentState("web-01") == OperationalStatusEnum.ACTIVE
    assert device_registry.getDevice("web-01").securityState == "COMPROMISED"
    print("    [PASS] Device 'web-01' is simultaneously Operational: ACTIVE and Security: COMPROMISED.")

    # Audit transition ledger
    history = state_transition_engine.getStateHistory("web-01")
    print(f"\n[*] Audit Trail for web-01: {len(history)} transitions recorded.")
    for h in history:
        print(f"    - [{h.timestamp}] {h.fromState.value:10s} -> {h.toState.value:10s} | Reason: {h.reason}")
    assert len(history) == 3

    print("\n" + "=" * 80)
    print("       ALL DAY 44 OPERATIONAL STATE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_operational_state_suite()