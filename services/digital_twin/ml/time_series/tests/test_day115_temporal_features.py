import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.features.feature_registry import temporal_feature_registry
from services.digital_twin.ml.time_series.features.temporal_feature_extractor import temporal_feature_extractor, TREND_CODES

def run_day115_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 115: TIME-SERIES FEATURE ENGINEERING AUDIT")
    print("=" * 80 + "\n")

    # 1. Rolling Statistics Mathematical Precision Audit
    print("[1/6] Auditing Rolling Statistics on Canonical Packet Sequence [20, 25, 30, 35, 50]...")
    seq_5 = [
        {"packet_rate": 20.0},
        {"packet_rate": 25.0},
        {"packet_rate": 30.0},
        {"packet_rate": 35.0},
        {"packet_rate": 50.0}
    ]
    feats = temporal_feature_extractor.extract_features(seq_5)
    assert len(feats) == 5

    # At step 2 (values [20, 25, 30]): mean = 25.0, std = sqrt(((20-25)^2 + (25-25)^2 + (30-25)^2)/3) = sqrt(50/3) = 4.0825
    obs_2 = feats[2]
    expected_mean_2 = 25.0
    expected_std_2 = round(float(np.std([20.0, 25.0, 30.0])), 4)
    print(f"    At Step 2: Computed Mean={obs_2['packet_rate_rolling_mean_w3']}, Expected={expected_mean_2}")
    print(f"    At Step 2: Computed Std={obs_2['packet_rate_rolling_std_w3']}, Expected={expected_std_2}")

    assert abs(obs_2["packet_rate_rolling_mean_w3"] - expected_mean_2) < 1e-3
    assert abs(obs_2["packet_rate_rolling_std_w3"] - expected_std_2) < 1e-3
    print("    [PASS] Rolling mean and volatility (standard deviation) verified.")

    # 2. Rate of Change & Safe Percentage Change Audit
    print("\n[2/6] Auditing Rate of Change and Percentage Change (50 -> 75 = +50%)...")
    test_roc_seq = [
        {"packet_rate": 50.0},
        {"packet_rate": 75.0},
        {"packet_rate": 0.0},  # Zero boundary
        {"packet_rate": 20.0}
    ]
    roc_feats = temporal_feature_extractor.extract_features(test_roc_seq)

    # 50 -> 75
    f_75 = roc_feats[1]
    print(f"    50 -> 75: Rate of Change = {f_75['packet_rate_rate_of_change']} (Expected: 25.0)")
    print(f"    50 -> 75: Percentage Change = {f_75['packet_rate_percentage_change']}% (Expected: 50.0%)")
    assert f_75["packet_rate_rate_of_change"] == 25.0
    assert f_75["packet_rate_percentage_change"] == 50.0

    # 0 -> 20 (Zero denominator handling)
    f_20 = roc_feats[3]
    print(f"    0 -> 20 (Zero Denominator): Pct Change = {f_20['packet_rate_percentage_change']}%")
    assert not np.isnan(f_20["packet_rate_percentage_change"])
    assert not np.isinf(f_20["packet_rate_percentage_change"])
    print("    [PASS] Rate of change and percentage calculations safe against zero division.")

    # 3. Trend Disambiguation Engine Audit
    print("\n[3/6] Auditing Trend Classification (INCREASING, DECREASING, STABLE, VOLATILE)...")
    inc_series = [10.0, 15.0, 22.0, 35.0, 50.0]
    dec_series = [50.0, 40.0, 30.0, 20.0, 10.0]
    stable_series = [20.0, 20.1, 19.9, 20.0, 20.2]
    volatile_series = [10.0, 60.0, 15.0, 65.0, 12.0]

    assert temporal_feature_extractor.calculate_trend(inc_series, threshold=2.0) == "INCREASING"
    assert temporal_feature_extractor.calculate_trend(dec_series, threshold=2.0) == "DECREASING"
    assert temporal_feature_extractor.calculate_trend(stable_series, threshold=1.0) == "STABLE"
    assert temporal_feature_extractor.calculate_trend(volatile_series, threshold=2.0) == "VOLATILE"
    print("    [PASS] Trend classification handles directional shifts and volatility.")

    # 4. Multi-Feature Telemetry Coverage
    print("\n[4/6] Auditing Full Major Network Telemetry Coverage...")
    multi_seq = [
        {
            "packet_rate": 100.0,
            "bytes": 50000.0,
            "failed_connections": 2.0,
            "dns_frequency": 1.5,
            "destination_diversity": 0.3
        },
        {
            "packet_rate": 180.0,
            "bytes": 120000.0,
            "failed_connections": 8.0,
            "dns_frequency": 6.0,
            "destination_diversity": 0.8
        }
    ]
    res_multi = temporal_feature_extractor.extract_features(multi_seq)[-1]
    expected_keys = [
        "packet_rate_lag_1", "bytes_rolling_mean_w3", "failed_connections_rate_of_change",
        "dns_frequency_rolling_mean_w3", "destination_diversity_trend"
    ]
    for k in expected_keys:
        assert k in res_multi
        print(f"    Feature Key Present: {k:<38} -> Value: {res_multi[k]}")
    print("    [PASS] Full multi-metric temporal coverage confirmed.")

    # 5. Configurable Lag Backfilling Policy
    print("\n[5/6] Auditing Boundary Lag Backfilling Policy...")
    # At step 0, t-1 and t-2 must backfill with step 0's value to prevent NaN
    first_step = feats[0]
    assert first_step["packet_rate_lag_1"] == 20.0
    assert first_step["packet_rate_lag_2"] == 20.0
    assert not any(v is None for v in first_step.values())
    print("    [PASS] Boundary lags backfill cleanly with zero null values.")

    # 6. Temporal Feature Registry Audit
    print("\n[6/6] Auditing Temporal Feature Registry Metadata Persistence...")
    reg_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "temporal_feature_registry.json"
    assert reg_file.exists()

    with open(reg_file, "r", encoding="utf-8") as f:
        stored_reg = json.load(f)

    assert len(stored_reg) >= 15
    sample_feat = stored_reg["packet_rate_rolling_mean_w3"]
    assert sample_feat["calculationType"] == "ROLLING_MEAN"
    assert sample_feat["windowSize"] == 3
    assert sample_feat["featureVersion"] == "ts-feat-v1.0"
    print(f"    Total Registered Temporal Features: {len(stored_reg)}")
    print(f"    Sample Definition: {sample_feat['featureName']} ({sample_feat['unit']})")
    print("    [PASS] Formal temporal feature registry validated on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 115 TIME-SERIES FEATURE ENGINEERING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day115_suite()