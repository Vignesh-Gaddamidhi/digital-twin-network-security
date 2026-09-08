import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.simulation import (
    ScenarioModel, SimulationStateEnum, TrafficProfileModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.simulation.engine.simulation_engine import (
    simulation_engine, InvalidSimulationStateTransitionError, ScenarioNotFoundError
)

def run_simulation_engine_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 50: SIMULATION ENGINE ARCHITECTURE & CLOCK AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    simulation_engine.resetSimulation()

    # 1. Provision Canonical Devices
    print("[1/5] Registering Target Devices in Device Registry...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    print("    [PASS] Registered client-01 and web-01.")

    # 2. Create Scenario
    print("\n[2/5] Creating Simulation Scenario (normal-office-001)...")
    scenario = ScenarioModel(
        scenarioId="normal-office-001",
        name="Normal Office Traffic",
        duration=10,  # 10 virtual seconds
        seed=12345,
        devices=["client-01", "web-01"],
        trafficProfiles=[
            TrafficProfileModel(name="Office-HTTPS", protocol="TCP", destinationPort=443, ratePerSecond=1.0)
        ]
    )
    simulation_engine.createSimulation(scenario)
    assert simulation_engine.state == SimulationStateEnum.CREATED
    print("    [PASS] Simulation state is CREATED.")

    # 3. Execution Lifecycle: Start -> Tick -> Pause -> Resume -> Stop -> Reset
    print("\n[3/5] Testing Complete Lifecycle (Start -> Tick -> Pause -> Resume -> Stop -> Reset)...")
    
    # Start
    simulation_engine.startSimulation()
    assert simulation_engine.state == SimulationStateEnum.RUNNING
    print("    [PASS] Transitioned to RUNNING.")

    # Tick 3 steps (0s -> 1s -> 2s -> 3s)
    evt1 = simulation_engine.tick(1.0)
    evt2 = simulation_engine.tick(1.0)
    evt3 = simulation_engine.tick(1.0)
    assert simulation_engine.getSimulationState().simCurrentTimeSeconds == 3.0
    assert len(simulation_engine.getSimulationEvents()) == 3
    print(f"    [PASS] Ticked to 3.0s. Generated event: {evt3.eventId} ({evt3.sourceDevice} -> {evt3.destinationDevice}:{evt3.destinationPort})")

    # Pause
    simulation_engine.pauseSimulation()
    assert simulation_engine.state == SimulationStateEnum.PAUSED
    print("    [PASS] Paused simulation at virtual T=3.0s.")

    # Verify tick while paused does not advance
    simulation_engine.tick(1.0)
    assert simulation_engine.getSimulationState().simCurrentTimeSeconds == 3.0
    print("    [PASS] Clock frozen during PAUSED state.")

    # Resume
    simulation_engine.resumeSimulation()
    assert simulation_engine.state == SimulationStateEnum.RUNNING
    print("    [PASS] Resumed simulation.")

    # Advance until completion (duration = 10s)
    for _ in range(7):
        simulation_engine.tick(1.0)

    assert simulation_engine.state == SimulationStateEnum.COMPLETED
    assert simulation_engine.getSimulationState().simCurrentTimeSeconds >= 10.0
    print("    [PASS] Simulation reached target duration and transitioned to COMPLETED.")

    # Reset
    simulation_engine.resetSimulation()
    assert simulation_engine.state == SimulationStateEnum.STOPPED
    assert simulation_engine.getSimulationState().simCurrentTimeSeconds == 0.0
    print("    [PASS] Simulation reset to STOPPED with clock cleared.")

    # 4. Deterministic Replay Verification
    print("\n[4/5] Testing Deterministic Replay with Identical Seed (12345)...")
    # Run 1
    simulation_engine.createSimulation(scenario)
    simulation_engine.startSimulation()
    run1_ports = [simulation_engine.tick(1.0).sourcePort for _ in range(3)]

    # Run 2
    simulation_engine.createSimulation(scenario)
    simulation_engine.startSimulation()
    run2_ports = [simulation_engine.tick(1.0).sourcePort for _ in range(3)]

    print(f"    Run 1 source ports: {run1_ports}")
    print(f"    Run 2 source ports: {run2_ports}")
    assert run1_ports == run2_ports
    print("    [PASS] Identical pseudo-random event sequence reproduced deterministically.")

    # 5. Boundary Condition & Rejection Tests
    print("\n[5/5] Executing Boundary Invariant & Rejection Tests...")

    # Start without scenario
    simulation_engine.resetSimulation()
    try:
        simulation_engine.startSimulation()
        assert False
    except ScenarioNotFoundError:
        print("    [PASS] Rejected start without configured scenario.")

    # Unknown device in scenario
    try:
        bad_scenario = ScenarioModel(
            scenarioId="bad-scen", name="Bad", duration=10, devices=["non-existent-device"]
        )
        simulation_engine.createSimulation(bad_scenario)
        assert False
    except DeviceNotFoundError:
        print("    [PASS] Rejected scenario referencing unprovisioned device.")

    # Illegal transition: CREATED -> PAUSED
    simulation_engine.createSimulation(scenario)
    try:
        simulation_engine.pauseSimulation()
        assert False
    except InvalidSimulationStateTransitionError:
        print("    [PASS] Safely rejected illegal transition (CREATED -> PAUSED).")

    print("\n" + "=" * 80)
    print("   ALL DAY 50 SIMULATION ENGINE ARCHITECTURE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_simulation_engine_suite()