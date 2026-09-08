import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.reproducible_simulation import (
    SimulationExecutionConfig, ReproducibleSimulationEvent, SimulationRunComparisonResult
)
from services.digital_twin.simulation.engine.reproducible_engine import (
    reproducible_engine, DuplicateSimulationIdError
)
from services.digital_twin.simulation.engine.simulation_logger import simulation_logger

def run_reproducible_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 51: REPRODUCIBLE SIMULATION ENVIRONMENT AUDIT")
    print("=" * 80 + "\n")

    reproducible_engine.clear()

    # 1. Run 1: Scenario A with Seed = 12345
    print("[1/5] Executing Run 1 (Scenario: Office-01, Seed: 12345, Duration: 5s)...")
    cfg1 = SimulationExecutionConfig(
        simulationId="sim-001",
        runId="run-alpha",
        scenarioId="Office-01",
        seed=12345,
        duration=5,
        tickInterval=1000,
        speed=1.0
    )
    reproducible_engine.initializeSimulation(cfg1)
    evts1 = reproducible_engine.runComplete(source_dev="client-01", dest_dev="web-01")
    print(f"    Run 1 completed. Total events generated: {len(evts1)}")
    for e in evts1:
        print(f"      Seq #{e.sequenceNumber} [T={e.simTimeSeconds}s] {e.sourceDevice}:{e.sourcePort} -> {e.destinationDevice}:{e.destinationPort} ({e.protocol}) Payload: {e.payloadSize} bytes")

    # 2. Run 2: Scenario A with Identical Seed = 12345
    print("\n[2/5] Executing Run 2 (Scenario: Office-01, Seed: 12345, Duration: 5s)...")
    cfg2 = SimulationExecutionConfig(
        simulationId="sim-002",
        runId="run-beta",
        scenarioId="Office-01",
        seed=12345,
        duration=5,
        tickInterval=1000,
        speed=1.0
    )
    reproducible_engine.initializeSimulation(cfg2)
    evts2 = reproducible_engine.runComplete(source_dev="client-01", dest_dev="web-01")
    print(f"    Run 2 completed. Total events generated: {len(evts2)}")

    # 3. Differential Comparison: Run 1 vs Run 2
    print("\n[3/5] Performing Differential Audit: Run 1 vs Run 2 (Expected: IDENTICAL)...")
    comparison = reproducible_engine.compareRuns("run-alpha", "run-beta")
    print(f"    Is Identical          : {comparison.isIdentical}")
    print(f"    Run 1 Events          : {comparison.totalEventsRun1}")
    print(f"    Run 2 Events          : {comparison.totalEventsRun2}")
    print(f"    Divergence Point      : {comparison.divergencePointSequence}")

    assert comparison.isIdentical is True
    assert comparison.totalEventsRun1 == 5
    assert comparison.totalEventsRun2 == 5

    # Byte-level check
    for e1, e2 in zip(evts1, evts2):
        assert e1.sequenceNumber == e2.sequenceNumber
        assert e1.simTimeSeconds == e2.simTimeSeconds
        assert e1.sourcePort == e2.sourcePort
        assert e1.destinationPort == e2.destinationPort
        assert e1.protocol == e2.protocol
        assert e1.payloadSize == e2.payloadSize
    print("    [PASS] Run 1 and Run 2 match byte-for-byte across all attributes!")

    # 4. Seed Divergence Verification (Seed = 98765)
    print("\n[4/5] Executing Run 3 with Divergent Seed (98765)...")
    cfg3 = SimulationExecutionConfig(
        simulationId="sim-003",
        runId="run-gamma",
        scenarioId="Office-01",
        seed=98765,
        duration=5
    )
    reproducible_engine.initializeSimulation(cfg3)
    evts3 = reproducible_engine.runComplete(source_dev="client-01", dest_dev="web-01")

    diff_comp = reproducible_engine.compareRuns("run-alpha", "run-gamma")
    print(f"    Is Identical with Seed 98765 : {diff_comp.isIdentical}")
    print(f"    Divergence Detected at Seq   : {diff_comp.divergencePointSequence}")
    print(f"    Divergence Explanation       : {diff_comp.divergenceReason}")
    assert diff_comp.isIdentical is False
    assert diff_comp.divergencePointSequence is not None
    print("    [PASS] Seed change produced distinct, non-matching pseudo-random stream.")

    # 5. Boundary Invariant & Rejection Tests
    print("\n[5/5] Executing Invariant & Rejection Tests...")

    # Negative duration
    try:
        SimulationExecutionConfig(simulationId="sim-bad", seed=12345, duration=-10)
        assert False
    except ValidationError:
        print("    [PASS] Rejected negative duration.")

    # Zero duration
    try:
        SimulationExecutionConfig(simulationId="sim-bad", seed=12345, duration=0)
        assert False
    except ValidationError:
        print("    [PASS] Rejected zero duration.")

    # Invalid speed
    try:
        SimulationExecutionConfig(simulationId="sim-bad", seed=12345, duration=10, speed=-1.5)
        assert False
    except ValidationError:
        print("    [PASS] Rejected negative speed multiplier.")

    # Duplicate simulation ID + Run ID
    try:
        reproducible_engine.initializeSimulation(cfg1)
        assert False
    except DuplicateSimulationIdError:
        print("    [PASS] Rejected duplicate simulation & run ID.")

    # JSONL file validation
    persisted_events = simulation_logger.readEvents(run_id="run-alpha")
    assert len(persisted_events) == 5
    assert persisted_events[0].sequenceNumber == 1
    print(f"    [PASS] Verified persistent stream logging in simulation-events.jsonl ({len(persisted_events)} events recovered).")

    print("\n" + "=" * 80)
    print("       ALL DAY 51 REPRODUCIBILITY TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_reproducible_suite()