import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.dataset.labeling.label_models import (
    LabeledDatasetSample, ModelBinaryLabel, ModelMulticlassLabel, LabelMethodEnum
)
from services.digital_twin.ml.dataset.splitting.split_models import SplitStrategyEnum
from services.digital_twin.ml.dataset.splitting.splitting_engine import dataset_splitting_engine

def generate_mock_labeled_samples() -> list:
    samples = []
    base_t = datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc)

    # 10 Scenario runs with 5 samples each (50 samples total)
    for run_idx in range(1, 11):
        run_id = f"RUN-{run_idx:03d}"
        is_attack = (run_idx > 5)
        scenario = f"SCN-PORTSCAN-{run_idx:03d}" if is_attack else "BASELINE_NORMAL"
        m_label = ModelMulticlassLabel.PORT_SCAN if is_attack else ModelMulticlassLabel.NORMAL
        b_label = ModelBinaryLabel.ANOMALOUS if is_attack else ModelBinaryLabel.NORMAL

        for step in range(5):
            ts = (base_t + timedelta(minutes=run_idx * 5, seconds=step * 10)).isoformat()
            s = LabeledDatasetSample(
                sampleId=f"SMP-{run_idx:02d}-{step:02d}",
                timestamp=ts,
                features={"packet_rate": float(10 + run_idx), "bytes": float(500 * run_idx), "tcp_ratio": 1.0},
                numericalVector=[float(10 + run_idx), float(500 * run_idx), 1.0],
                scenario_label=scenario,
                binary_label=b_label,
                multiclass_label=m_label,
                label_source=f"SIMULATION::{run_id}",
                label_confidence=1.0,
                label_method=LabelMethodEnum.DETERMINISTIC_SCENARIO,
                metadata={"runId": run_id, "simulationId": run_id}
            )
            samples.append(s)
    return samples

def run_day97_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 97: TRAIN/TEST SPLIT & ANTI-LEAKAGE AUDIT")
    print("=" * 80 + "\n")

    dataset_splitting_engine.clear()
    samples = generate_mock_labeled_samples()
    assert len(samples) == 50

    # 1. Temporal Partitioning Audit
    print("[1/5] Auditing Temporal Partitioning (Chronological Non-Inversion)...")
    train_t, test_t, meta_t = dataset_splitting_engine.split_dataset(
        samples, strategy=SplitStrategyEnum.TEMPORAL, train_ratio=0.80
    )
    print(f"    Train Samples: {meta_t.trainSamplesCount}, Test Samples: {meta_t.testSamplesCount}")
    assert meta_t.trainSamplesCount == 40
    assert meta_t.testSamplesCount == 10

    max_train_ts = max(r.timestamp for r in train_t)
    min_test_ts = min(r.timestamp for r in test_t)
    print(f"    Max Train Timestamp : {max_train_ts}")
    print(f"    Min Test Timestamp  : {min_test_ts}")
    assert max_train_ts <= min_test_ts
    assert meta_t.temporalIsolationPassed is True
    print("    [PASS] Temporal isolation confirmed: No future telemetry leaked into train set.")

    # 2. Group-Aware Partitioning Audit
    print("\n[2/5] Auditing Group-Aware Partitioning (Simulation Run Disjointness)...")
    train_g, test_g, meta_g = dataset_splitting_engine.split_dataset(
        samples, strategy=SplitStrategyEnum.GROUP, train_ratio=0.80
    )
    train_groups = {r.groupId for r in train_g}
    test_groups = {r.groupId for r in test_g}
    overlap = train_groups.intersection(test_groups)

    print(f"    Train Unique Groups: {len(train_groups)}, Test Unique Groups: {len(test_groups)}")
    print(f"    Overlap Groups Count: {len(overlap)}")
    assert len(overlap) == 0
    assert meta_g.disjointGroupsPassed is True
    print("    [PASS] Group isolation confirmed: Zero simulation runs leak across train and test partitions.")

    # 3. Stratified Partitioning Audit
    print("\n[3/5] Auditing Stratified Partitioning (Class Balance Preservation)...")
    train_s, test_s, meta_s = dataset_splitting_engine.split_dataset(
        samples, strategy=SplitStrategyEnum.STRATIFIED, train_ratio=0.80
    )
    print(f"    Train Class Distribution : {meta_s.trainClassDistribution}")
    print(f"    Test Class Distribution  : {meta_s.testClassDistribution}")

    assert "NORMAL" in meta_s.trainClassDistribution and "NORMAL" in meta_s.testClassDistribution
    assert "PORT_SCAN" in meta_s.trainClassDistribution and "PORT_SCAN" in meta_s.testClassDistribution
    print("    [PASS] Stratified distribution confirmed: Target classes present across both sets.")

    # 4. Disjoint Sample ID Verification
    print("\n[4/5] Auditing Disjoint Sample Identifier Invariants...")
    train_ids = {r.sampleId for r in train_g}
    test_ids = {r.sampleId for r in test_g}
    assert len(train_ids.intersection(test_ids)) == 0
    assert meta_g.disjointSamplesPassed is True
    print(f"    [PASS] Zero duplicate sample IDs between train ({len(train_ids)}) and test ({len(test_ids)}).")

    # 5. Persistent Disk Storage Verification
    print("\n[5/5] Auditing Output File Persistence (train.jsonl & test.jsonl)...")
    assert dataset_splitting_engine.train_file.exists()
    assert dataset_splitting_engine.test_file.exists()

    with open(dataset_splitting_engine.train_file, "r", encoding="utf-8") as f:
        train_lines = f.readlines()
    with open(dataset_splitting_engine.test_file, "r", encoding="utf-8") as f:
        test_lines = f.readlines()

    active_train_count = len(dataset_splitting_engine.train_records)
    active_test_count = len(dataset_splitting_engine.test_records)

    print(f"    datasets/split/train.jsonl line count: {len(train_lines)} (expected: {active_train_count})")
    print(f"    datasets/split/test.jsonl line count : {len(test_lines)} (expected: {active_test_count})")
    assert len(train_lines) == active_train_count
    assert len(test_lines) == active_test_count
    print("    [PASS] Partitions persisted to datasets/split/ with verified integrity.")

    print("\n" + "=" * 80)
    print("       ALL DAY 97 TRAIN/TEST SPLIT TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day97_suite()