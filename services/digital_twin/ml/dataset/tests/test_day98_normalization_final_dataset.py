import sys
import json
import math
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.dataset.splitting.split_models import SplitSampleRecord, PartitionEnum, SplitStrategyEnum
from services.digital_twin.ml.dataset.normalization.normalization_engine import feature_normalization_engine

def generate_mock_train_test_records() -> tuple:
    train_recs = []
    test_recs = []
    base_t = datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc)

    # 40 Train records
    for i in range(40):
        is_dos = (i >= 20)
        pkt_rate = 500.0 if is_dos else 10.0
        bytes_val = 250000.0 if is_dos else 1200.0
        r = SplitSampleRecord(
            sampleId=f"SMP-TR-{i:02d}",
            split=PartitionEnum.TRAIN,
            splitStrategy=SplitStrategyEnum.TEMPORAL,
            timestamp=(base_t + timedelta(seconds=i)).isoformat(),
            groupId="RUN-01",
            scenarioId="SCN-DOS-001" if is_dos else "BASELINE_NORMAL",
            features={
                "packet_rate": pkt_rate,
                "bytes": bytes_val,
                "bytes_per_second": bytes_val,
                "connection_frequency": 2.0 if is_dos else 0.5,
                "port_22_ratio": 0.0,
                "port_53_ratio": 0.0,
                "port_80_ratio": 1.0 if not is_dos else 0.0,
                "port_443_ratio": 1.0 if is_dos else 0.0,
                "port_other_ratio": 0.0,
                "unique_destination_ports": 1.0,
                "flow_duration": 1.0,
                "tcp_ratio": 1.0,
                "udp_ratio": 0.0,
                "icmp_ratio": 0.0,
                "failed_connections": 0.0,
                "failed_connection_rate": 0.0,
                "dns_queries": 0.0,
                "dns_frequency": 0.0,
                "destination_diversity": 1.0,
                "unique_destination_ratio": 1.0
            },
            numericalVector=[pkt_rate, bytes_val],
            binary_label="ANOMALOUS" if is_dos else "NORMAL",
            multiclass_label="DOS_LIKE" if is_dos else "NORMAL"
        )
        train_recs.append(r)

    # 10 Test records
    for j in range(10):
        is_dos = (j >= 5)
        pkt_rate = 600.0 if is_dos else 8.0
        bytes_val = 300000.0 if is_dos else 1000.0
        r = SplitSampleRecord(
            sampleId=f"SMP-TE-{j:02d}",
            split=PartitionEnum.TEST,
            splitStrategy=SplitStrategyEnum.TEMPORAL,
            timestamp=(base_t + timedelta(seconds=100 + j)).isoformat(),
            groupId="RUN-02",
            scenarioId="SCN-DOS-001" if is_dos else "BASELINE_NORMAL",
            features={
                "packet_rate": pkt_rate,
                "bytes": bytes_val,
                "bytes_per_second": bytes_val,
                "connection_frequency": 2.5 if is_dos else 0.4,
                "port_22_ratio": 0.0,
                "port_53_ratio": 0.0,
                "port_80_ratio": 1.0 if not is_dos else 0.0,
                "port_443_ratio": 1.0 if is_dos else 0.0,
                "port_other_ratio": 0.0,
                "unique_destination_ports": 1.0,
                "flow_duration": 1.0,
                "tcp_ratio": 1.0,
                "udp_ratio": 0.0,
                "icmp_ratio": 0.0,
                "failed_connections": 0.0,
                "failed_connection_rate": 0.0,
                "dns_queries": 0.0,
                "dns_frequency": 0.0,
                "destination_diversity": 1.0,
                "unique_destination_ratio": 1.0
            },
            numericalVector=[pkt_rate, bytes_val],
            binary_label="ANOMALOUS" if is_dos else "NORMAL",
            multiclass_label="DOS_LIKE" if is_dos else "NORMAL"
        )
        test_recs.append(r)

    return train_recs, test_recs

def run_day98_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 98: NORMALIZATION & FINAL DATASET QUALITY AUDIT")
    print("=" * 80 + "\n")

    feature_normalization_engine.clear()
    train_in, test_in = generate_mock_train_test_records()

    # 1. Fit-Only-On-Train & Zero Leakage Verification
    print("[1/6] Auditing Fit-Only-On-Train Parameter Estimation...")
    scaler = feature_normalization_engine.fit_scaler(train_in)
    assert scaler.fittedOnSamplesCount == 40
    assert "packet_rate" in scaler.parameters
    assert "bytes" in scaler.parameters

    # Expected train mean for packet_rate: (20 * 10 + 20 * 500) / 40 = 255.0
    pr_mean = scaler.parameters["packet_rate"].mean
    print(f"    Train packet_rate Mean: {pr_mean} (Expected: 255.0)")
    assert abs(pr_mean - 255.0) < 0.1
    print("    [PASS] Scaler parameters calculated exclusively on train partition.")

    # 2. Variance Flooring Audit (Division by Zero Prevention)
    print("\n[2/6] Auditing Variance Flooring on Constant Features (icmp_ratio)...")
    icmp_param = scaler.parameters["icmp_ratio"]
    print(f"    Constant Feature icmp_ratio StdDev: {icmp_param.stdDev}")
    assert icmp_param.stdDev >= 1e-6
    print("    [PASS] Zero-variance feature floored to 1e-6 without numerical instability.")

    # 3. Execution & Transformation Integrity
    print("\n[3/6] Executing Complete Dataset Normalization (Train & Test)...")
    train_out, test_out, report = feature_normalization_engine.process_and_persist_dataset(train_in, test_in)

    assert len(train_out) == 40
    assert len(test_out) == 10
    print(f"    Normalized Train Records Count: {len(train_out)}")
    print(f"    Normalized Test Records Count : {len(test_out)}")

    # Verify that test transformation used train scaler
    t0_pr = test_out[0].normalizedFeatures["packet_rate"]
    expected_t0_pr = round((8.0 - pr_mean) / scaler.parameters["packet_rate"].stdDev, 6)
    assert abs(t0_pr - expected_t0_pr) < 1e-4
    print(f"    Test Sample [0] Normalized packet_rate: {t0_pr} (Matched Train Scaler)")
    print("    [PASS] Test partition transformed strictly using train scaler parameters.")

    # 4. Separation of X Matrix from Y Targets
    print("\n[4/6] Auditing 20-Dimensional X Matrix vs Target Y Decoupling...")
    sample_vec = train_out[0].normalizedVector
    assert len(sample_vec) == 20
    assert all(isinstance(x, float) for x in sample_vec)
    assert not any(math.isnan(x) for x in sample_vec)
    assert train_out[0].binary_label in ("NORMAL", "ANOMALOUS")
    assert train_out[0].multiclass_label in ("NORMAL", "DOS_LIKE")
    print("    [PASS] Predictor matrix X is pure 20-dim float vector; labels Y strictly decoupled.")

    # 5. File Persistence Integrity
    print("\n[5/6] Auditing Persistent Dataset & Scaler Files on Disk...")
    train_path = ROOT_DIR / "datasets" / "normalized" / "train" / "train_normalized.jsonl"
    test_path = ROOT_DIR / "datasets" / "normalized" / "test" / "test_normalized.jsonl"
    scaler_path = ROOT_DIR / "datasets" / "metadata" / "scaler_v1.0.json"
    meta_path = ROOT_DIR / "datasets" / "metadata" / "dataset_v1.0_metadata.json"

    for p in [train_path, test_path, scaler_path, meta_path]:
        assert p.exists(), f"File {p} was not written to disk!"

    with open(train_path, "r", encoding="utf-8") as f:
        assert len(f.readlines()) == 40
    with open(test_path, "r", encoding="utf-8") as f:
        assert len(f.readlines()) == 10

    print("    [PASS] All 4 dataset and metadata artifacts persisted to disk.")

    # 6. Quality Report & Versioning Audit
    print("\n[6/6] Auditing Final Dataset Quality Report (dataset-v1.0)...")
    assert report.datasetVersion == "1.0.0"
    assert report.zeroLeakageVerified is True
    assert report.scalerFittedExclusivelyOnTrain is True
    assert report.overallQualityStatus == "PASSED_PRODUCTION_GRADE"
    print(f"    Quality Status: {report.overallQualityStatus}")
    print(f"    Class Distribution Train: {report.classDistributionTrain}")
    print(f"    Class Distribution Test : {report.classDistributionTest}")
    print("    [PASS] Complete dataset quality checks passed with 100% compliance.")

    print("\n" + "=" * 80)
    print("       ALL DAY 98 NORMALIZATION TESTS PASSED CLEANLY")
    print("       PHASE 11: MACHINE LEARNING DATASET GRADUATED SUCCESSFULLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day98_suite()