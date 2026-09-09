import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.attack_indicators import (
    ExpectedIndicatorModel, IndicatorTypeEnum, IndicatorDirectionEnum,
    IndicatorSeverityEnum
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum,
    UnifiedTrafficEventModel
)
from packages.shared_types.src.traffic_pattern import (
    GenericTrafficPatternModel, PatternTypeEnum, ConnectionBehaviourEnum,
    PatternTimingConfig
)
from services.digital_twin.simulation.attack.indicators.indicator_registry import indicator_registry
from services.digital_twin.simulation.attack.indicators.indicator_matcher import indicator_matcher
from services.digital_twin.simulation.attack.generators.pattern_generator_engine import pattern_generator_engine

def run_expected_indicators_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 68: EXPECTED INDICATORS FRAMEWORK AUDIT")
    print("=" * 80 + "\n")

    # 1. Catalog Check
    print("[1/5] Auditing Standard Indicator Catalog...")
    catalog = indicator_registry.listAll()
    assert len(catalog) >= 5
    types_in_cat = {c.type for c in catalog}
    assert IndicatorTypeEnum.UNUSUAL_PORT_ACTIVITY in types_in_cat
    assert IndicatorTypeEnum.HIGH_FAILED_CONNECTION_RATE in types_in_cat
    assert IndicatorTypeEnum.TRAFFIC_VOLUME_SPIKE in types_in_cat
    print(f"    [PASS] Standard catalog verified with {len(catalog)} baseline signatures.")

    # 2. Port Sweep Scenario Indicator Matching
    print("\n[2/5] Testing UNUSUAL_PORT_ACTIVITY Signature Detection...")
    pat = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.SEQUENTIAL,
        sourceDevice="client-01",
        targetDevice="server-01",
        destinationPorts=[21, 22, 23, 25, 80, 443, 8080],
        connectionBehaviour=ConnectionBehaviourEnum.RESET_IMMEDIATE,
        timing=PatternTimingConfig(durationSeconds=5.0, rateEventsPerSecond=2.0),
        seed=12345
    )
    _, events = pattern_generator_engine.generate_events(pat)

    ind_port = ExpectedIndicatorModel(
        indicatorId="EXP-PORTS-01",
        type=IndicatorTypeEnum.UNUSUAL_PORT_ACTIVITY,
        description="Expect > 5 unique ports probed",
        metric="unique_destination_ports",
        threshold=5.0,
        direction=IndicatorDirectionEnum.GREATER_THAN
    )

    report = indicator_matcher.verify_scenario_indicators("SCN-PORTSCAN-001", [ind_port], events, duration_seconds=5.0)
    assert report.matchedCount == 1
    assert report.missedCount == 0
    assert report.precisionScore == 1.0
    print("    [PASS] UNUSUAL_PORT_ACTIVITY accurately matched against 7-port sweep.")

    # 3. High Failed Connection Rate Matching
    print("\n[3/5] Testing HIGH_FAILED_CONNECTION_RATE Detection...")
    failed_events = []
    base_t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    for i in range(15):
        failed_events.append(UnifiedTrafficEventModel(
            simulationId="sim-test",
            sourceDevice="client-01",
            destinationDevice="server-01",
            protocol=TransportProtocolEnum.TCP,
            sourcePort=50000 + i,
            destinationPort=22,
            bytes=60,
            packets=1,
            direction=TrafficDirectionEnum.OUTBOUND,
            tcpState=SimulatedTcpStateEnum.FAILED,
            timestamp=(base_t + timedelta(seconds=i*0.2)).isoformat(),
            details={"flag": "RST"}
        ))

    ind_fail = ExpectedIndicatorModel(
        indicatorId="EXP-FAIL-01",
        type=IndicatorTypeEnum.HIGH_FAILED_CONNECTION_RATE,
        description="Expect > 10 failed connections",
        metric="failed_connections_count",
        threshold=10.0,
        direction=IndicatorDirectionEnum.GREATER_THAN
    )

    report_fail = indicator_matcher.verify_scenario_indicators("SCN-BRUTEFORCE-001", [ind_fail], failed_events, duration_seconds=3.0)
    assert report_fail.matchedCount == 1
    assert report_fail.matchedIndicators[0].observedValue == 15.0
    print("    [PASS] HIGH_FAILED_CONNECTION_RATE verified (15 failed handshakes observed vs > 10 threshold).")

    # 4. Periodic Beaconing (Low Timing Variance) Matching
    print("\n[4/5] Testing PERIODIC_TRAFFIC (C2 Beacon) Detection...")
    beacon_pat = GenericTrafficPatternModel(
        patternType=PatternTypeEnum.PERIODIC,
        sourceDevice="client-01",
        targetDevice="c2-server",
        destinationPorts=[443],
        timing=PatternTimingConfig(durationSeconds=10.0, rateEventsPerSecond=1.0, jitterSeconds=0.0),
        seed=12345
    )
    _, beacon_events = pattern_generator_engine.generate_events(beacon_pat)

    ind_beacon = ExpectedIndicatorModel(
        indicatorId="EXP-BEACON-01",
        type=IndicatorTypeEnum.PERIODIC_TRAFFIC,
        description="Expect inter-packet variance < 0.05s",
        metric="interval_variance_seconds",
        threshold=0.05,
        direction=IndicatorDirectionEnum.LESS_THAN
    )

    report_beacon = indicator_matcher.verify_scenario_indicators("SCN-BEACON-001", [ind_beacon], beacon_events, duration_seconds=10.0)
    assert report_beacon.matchedCount == 1
    assert report_beacon.matchedIndicators[0].observedValue < 0.05
    print("    [PASS] PERIODIC_TRAFFIC verified: Beacon intervals confirmed near-zero variance.")

    # 5. Missed Indicator Identification & Precision Scoring
    print("\n[5/5] Auditing Missed Indicator Catching & Precision Scoring...")
    unmet_ind = ExpectedIndicatorModel(
        indicatorId="EXP-EXFIL-UNMET",
        type=IndicatorTypeEnum.UNUSUAL_OUTBOUND_VOLUME,
        description="Expect > 100000 bytes",
        metric="outbound_bytes_total",
        threshold=100000.0,
        direction=IndicatorDirectionEnum.GREATER_THAN
    )

    mixed_report = indicator_matcher.verify_scenario_indicators(
        "SCN-MIXED-001",
        [ind_port, unmet_ind],
        events, # ~448 bytes total
        duration_seconds=5.0
    )

    assert mixed_report.totalExpected == 2
    assert mixed_report.matchedCount == 1
    assert mixed_report.missedCount == 1
    assert mixed_report.precisionScore == 0.50
    assert mixed_report.missedExpectedIndicators[0].indicatorId == "EXP-EXFIL-UNMET"
    print("    [PASS] Precision scoring accurately penalized unmet indicator (0.50 precision).")

    print("\n" + "=" * 80)
    print("       ALL DAY 68 EXPECTED INDICATORS TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_expected_indicators_suite()