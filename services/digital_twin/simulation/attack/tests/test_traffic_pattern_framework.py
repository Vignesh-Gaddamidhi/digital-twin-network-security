import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.traffic_pattern import (
    GenericTrafficPatternModel, PatternTypeEnum, ConnectionBehaviourEnum,
    PatternTimingConfig
)
from services.digital_twin.simulation.attack.generators.pattern_generator_engine import pattern_generator_engine

def run_traffic_pattern_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 67: TRAFFIC PATTERN FRAMEWORK AUDIT")
    print("=" * 80 + "\n")

    # 1. SEQUENTIAL Port Scan Pattern (21, 22, 25, 53, 80, 443, 8080)
    print("[1/5] Auditing SEQUENTIAL Port Sweep Pattern...")
    seq_pat = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.SEQUENTIAL,
        sourceDevice="client-01",
        targetDevice="server-01",
        destinationPorts=[21, 22, 25, 53, 80, 443, 8080],
        connectionBehaviour=ConnectionBehaviourEnum.RESET_IMMEDIATE,
        timing=PatternTimingConfig(durationSeconds=7.0, rateEventsPerSecond=1.0),
        seed=12345
    )
    res_seq, evts_seq = pattern_generator_engine.generate_events(seq_pat)
    print(f"    Emitted {res_seq.totalPacketsEmitted} sequential probes across: {res_seq.portsTargeted}")
    assert len(evts_seq) == 7
    # Verify cyclic sequential progression
    expected_ports = [21, 22, 25, 53, 80, 443, 8080]
    for idx, p in enumerate(expected_ports):
        assert evts_seq[idx].destinationPort == p
        assert evts_seq[idx].details.get("action") == "EXPECT_RST"
    print("    [PASS] SEQUENTIAL pattern verified across all 7 target ports.")

    # 2. BURST Waveform Test
    print("\n[2/5] Auditing BURST Waveform...")
    burst_pat = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.BURST,
        sourceDevice="client-01",
        targetDevice="server-01",
        destinationPorts=[80],
        timing=PatternTimingConfig(durationSeconds=3.0, rateEventsPerSecond=5.0),
        seed=12345
    )
    res_burst, evts_burst = pattern_generator_engine.generate_events(burst_pat)
    print(f"    Emitted {res_burst.totalPacketsEmitted} burst packets over 3 seconds.")
    assert len(evts_burst) == 15 # 3 bursts of 5 packets
    print("    [PASS] BURST waveform verified.")

    # 3. Waveform Coverage: PERIODIC, REPEATED, RANDOMIZED, GRADUAL_INCREASE, GRADUAL_DECREASE
    print("\n[3/5] Auditing Remaining 5 Waveform Implementations...")
    for ptype in [
        PatternTypeEnum.PERIODIC,
        PatternTypeEnum.REPEATED,
        PatternTypeEnum.RANDOMIZED,
        PatternTypeEnum.GRADUAL_INCREASE,
        PatternTypeEnum.GRADUAL_DECREASE
    ]:
        p = GenericTrafficPatternModel(
            patternType=ptype,
            sourceDevice="client-01",
            targetDevice="server-01",
            destinationPorts=[443],
            timing=PatternTimingConfig(durationSeconds=4.0, rateEventsPerSecond=4.0),
            seed=12345
        )
        res, evts = pattern_generator_engine.generate_events(p)
        assert len(evts) > 0
        print(f"    [PASS] Waveform {ptype.value:<16} emitted {len(evts)} packets.")

    # 4. Deterministic Reproducibility Audit (Run A == Run B, Run A != Run C)
    print("\n[4/5] Auditing Deterministic Reproducibility (Seed 12345 vs 99999)...")
    pat_a = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.RANDOMIZED,
        destinationPorts=[21, 22, 80, 443, 8080],
        timing=PatternTimingConfig(durationSeconds=5.0, rateEventsPerSecond=4.0, jitterSeconds=0.05),
        seed=12345
    )
    pat_b = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.RANDOMIZED,
        destinationPorts=[21, 22, 80, 443, 8080],
        timing=PatternTimingConfig(durationSeconds=5.0, rateEventsPerSecond=4.0, jitterSeconds=0.05),
        seed=12345
    )
    pat_c = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.RANDOMIZED,
        destinationPorts=[21, 22, 80, 443, 8080],
        timing=PatternTimingConfig(durationSeconds=5.0, rateEventsPerSecond=4.0, jitterSeconds=0.05),
        seed=99999
    )

    _, evts_a = pattern_generator_engine.generate_events(pat_a)
    _, evts_b = pattern_generator_engine.generate_events(pat_b)
    _, evts_c = pattern_generator_engine.generate_events(pat_c)

    assert len(evts_a) == len(evts_b)
    for i in range(len(evts_a)):
        assert evts_a[i].destinationPort == evts_b[i].destinationPort
        assert evts_a[i].sourcePort == evts_b[i].sourcePort
        assert evts_a[i].timestamp == evts_b[i].timestamp

    print("    [PASS] VERIFIED: Run A == Run B (Deterministic Invariant Equivalence).")
    assert [e.destinationPort for e in evts_a] != [e.destinationPort for e in evts_c]
    print("    [PASS] VERIFIED: Run A != Run C (Controlled Deviation Confirmed).")

    # 5. Validation Invariants
    print("\n[5/5] Auditing Pattern Validation Guardrails...")
    try:
        bad_pat = GenericTrafficPatternModel(destinationPorts=[])
        pattern_generator_engine.validate_pattern(bad_pat)
        assert False
    except ValueError:
        print("    [PASS] Accurately rejected empty destination port list.")

    print("\n" + "=" * 80)
    print("       ALL DAY 67 TRAFFIC PATTERN FRAMEWORK TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_traffic_pattern_suite()