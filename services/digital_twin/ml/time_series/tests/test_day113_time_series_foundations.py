import sys
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.features.temporal_feature_engine import temporal_feature_engine
from services.digital_twin.ml.time_series.features.time_series_models import TimeSeriesObservation

def run_day113_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 113: TIME-SERIES FOUNDATIONS AUDIT")
    print("=" * 80 + "\n")

    temporal_feature_engine.clear()

    # 1. Canonical Sequential Escalation Trajectory (Day 113 Specification)
    print("[1/6] Auditing Canonical Escalation Sequence (20 -> 22 -> 25 -> 31 -> 42 -> 65 -> 110 -> 180)...")
    escalation_stream = [
        {"packet_rate": 20.0, "bytes_per_second": 10000.0, "label": "NORMAL"},
        {"packet_rate": 22.0, "bytes_per_second": 11000.0, "label": "NORMAL"},
        {"packet_rate": 25.0, "bytes_per_second": 13000.0, "label": "NORMAL"},
        {"packet_rate": 31.0, "bytes_per_second": 18000.0, "label": "NORMAL"},
        {"packet_rate": 42.0, "bytes_per_second": 30000.0, "label": "ANOMALOUS"},
        {"packet_rate": 65.0, "bytes_per_second": 60000.0, "label": "ANOMALOUS"},
        {"packet_rate": 110.0, "bytes_per_second": 120000.0, "label": "ANOMALOUS"},
        {"packet_rate": 180.0, "bytes_per_second": 250000.0, "label": "ANOMALOUS"}
    ]

    observations = temporal_feature_engine.process_telemetry_stream(
        raw_stream=escalation_stream,
        device_id="GATEWAY-01"
    )

    assert len(observations) == 8
    print(f"    Total Processed Time-Series Observations: {len(observations)}")
    print("    [PASS] Sequence processed chronologically.")

    # 2. Lag Features Audit (t-1, t-2, t-3)
    print("\n[2/6] Auditing Lag Features Precision...")
    # At t=3 (packet_rate=31.0): t-1 should be 25.0, t-2 should be 22.0, t-3 should be 20.0
    obs_3 = observations[3]
    lags_3 = obs_3.lagFeatures["packetRate"]
    print(f"    Observation at t=3 (pkt_rate={obs_3.packetRate}): Lags={lags_3}")
    assert lags_3[0] == 25.0  # t-1
    assert lags_3[1] == 22.0  # t-2
    assert lags_3[2] == 20.0  # t-3
    print("    [PASS] Lag operators (t-1, t-2, t-3) match historical stream values.")

    # 3. Rolling Statistics Audit
    print("\n[3/6] Auditing Rolling Window Statistics (Window w=3)...")
    # At t=2 (vals: 20, 22, 25): mean = (20+22+25)/3 = 22.3333, min=20, max=25, median=22
    obs_2 = observations[2]
    rf_w3 = obs_2.rollingFeatures["packetRate_w3"]
    expected_mean = round((20.0 + 22.0 + 25.0) / 3.0, 4)
    print(f"    At t=2: Computed Mean={rf_w3.mean}, Expected={expected_mean}")
    assert abs(rf_w3.mean - expected_mean) < 1e-4
    assert rf_w3.minVal == 20.0
    assert rf_w3.maxVal == 25.0
    assert rf_w3.median == 22.0
    print("    [PASS] Rolling mean, min, max, and median verified.")

    # 4. Temporal Derivatives (Rate of Change, Velocity, Acceleration)
    print("\n[4/6] Auditing Derivatives (Rate of Change, Velocity, Acceleration)...")
    # At t=7 (curr=180.0, prev=110.0, prev_prev=65.0, interval=5.0s)
    # roc = 180 - 110 = 70.0
    # vel = 70.0 / 5.0 = 14.0 pkts/s
    # prev_vel = (110.0 - 65.0) / 5.0 = 45.0 / 5.0 = 9.0 pkts/s
    # acc = (14.0 - 9.0) / 5.0 = 5.0 / 5.0 = 1.0 pkts/s^2
    obs_7 = observations[7]
    dyn_7 = obs_7.dynamics["packetRate"]
    print(f"    At t=7 (Peak 180 pkts): RateOfChange={dyn_7.rateOfChange}, Velocity={dyn_7.velocity}, Acceleration={dyn_7.acceleration}")

    assert dyn_7.rateOfChange == 70.0
    assert dyn_7.velocity == 14.0
    assert dyn_7.acceleration == 1.0
    assert dyn_7.trendDirection == "INCREASING"
    print("    [PASS] Velocity and Acceleration derivatives mathematically verified.")

    # 5. Pre-Impact vs. Impact Early-Warning Stage Separation
    print("\n[5/6] Auditing Threat Progression Stages (BASELINE -> PRE_IMPACT -> IMPACT)...")
    stages = [obs.stage for obs in observations]
    print(f"    Observed Stage Trajectory: {stages}")

    assert observations[0].stage == "BASELINE"
    assert "PRE_IMPACT" in stages
    assert observations[-1].stage == "IMPACT"
    print("    [PASS] Clear demarcation between Baseline, Pre-Impact incubation, and Impact stage.")

    # 6. Flat Feature Vector Formulation
    print("\n[6/6] Auditing Flat Feature Vector Generation...")
    flat_vec = obs_7.to_flat_feature_vector()
    print(f"    Flat Vector Length: {len(flat_vec)}")
    print(f"    Sample Vector Elements: {flat_vec[:8]}")

    assert len(flat_vec) == 16  # 8 base features + 8 dynamics
    assert flat_vec[0] == 180.0
    print("    [PASS] Flat numeric vector compatible with recurrent neural tensors.")

    print("\n" + "=" * 80)
    print("       ALL DAY 113 TIME-SERIES FOUNDATIONS TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day113_suite()