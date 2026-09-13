import sys
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.features.temporal_feature_engine import temporal_feature_engine
from services.digital_twin.ml.time_series.windows.window_models import SlidingWindowConfig, TemporalSequence
from services.digital_twin.ml.time_series.windows.sliding_window_generator import sliding_window_generator, SlidingWindowGenerator
from services.digital_twin.ml.time_series.sequences.sequence_dataset_builder import sequence_dataset_builder

def run_day114_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 114: SLIDING WINDOWS & SEQUENCES AUDIT")
    print("=" * 80 + "\n")

    # 1. Verification of Sequence Count Mathematical Invariant
    print("[1/6] Auditing Window Size, Step Size, and Sequence Count Invariant...")
    # 20 observations, T=5, S=1, H=2 -> Total = 20 - (5 + 2) + 1 = 14 sequences
    stream_20 = [{"packet_rate": float(i * 10), "label": "NORMAL"} for i in range(20)]
    obs_20 = temporal_feature_engine.process_telemetry_stream(stream_20)

    cfg = SlidingWindowConfig(windowSize=5, stepSize=1, predictionHorizon=2)
    gen = SlidingWindowGenerator(config=cfg)
    seqs = gen.create_sequences(obs_20)

    print(f"    Total Observations: 20 | Window T: 5 | Step S: 1 | Horizon H: 2")
    print(f"    Extracted Sequences Count: {len(seqs)} (Expected: 14)")
    assert len(seqs) == 14

    # Test Stride S=2: (20 - 7) / 2 + 1 = 7 sequences
    cfg_s2 = SlidingWindowConfig(windowSize=5, stepSize=2, predictionHorizon=2)
    gen_s2 = SlidingWindowGenerator(config=cfg_s2)
    seqs_s2 = gen_s2.create_sequences(obs_20)
    print(f"    Extracted Sequences Count with Step S=2: {len(seqs_s2)} (Expected: 7)")
    assert len(seqs_s2) == 7
    print("    [PASS] Sequence count mathematical invariants verified across strides.")

    # 2. Correct Sequential Indexing & Slice Boundaries
    print("\n[2/6] Auditing Window Slices and Horizon Boundary Invariants...")
    # For sequence 0: window covers obs 0..4, horizon covers obs 5..6
    s0 = seqs[0]
    assert s0.startIndex == 0
    assert s0.endIndex == 4
    assert s0.horizonStartIndex == 5
    assert s0.horizonEndIndex == 6
    assert len(s0.featureMatrix) == 5

    # For sequence 1: window covers obs 1..5, horizon covers obs 6..7
    s1 = seqs[1]
    assert s1.startIndex == 1
    assert s1.endIndex == 5
    assert s1.horizonStartIndex == 6
    assert s1.horizonEndIndex == 7

    print(f"    Seq 0 Window Range: [{s0.startIndex}..{s0.endIndex}] -> Horizon: [{s0.horizonStartIndex}..{s0.horizonEndIndex}]")
    print(f"    Seq 1 Window Range: [{s1.startIndex}..{s1.endIndex}] -> Horizon: [{s1.horizonStartIndex}..{s1.horizonEndIndex}]")
    print("    [PASS] Strict boundary alignment confirmed without index drift.")

    # 3. Prediction Horizon Target Lookahead Logic
    print("\n[3/6] Auditing Future Threat Target Labeling over Horizon H...")
    # Create stream where attack occurs strictly at step 10
    threat_stream = []
    for t in range(15):
        lbl = "DOS_LIKE" if t == 10 else "NORMAL"
        threat_stream.append({"packet_rate": 200.0 if t == 10 else 20.0, "label": lbl})

    threat_obs = temporal_feature_engine.process_telemetry_stream(threat_stream)
    # T=5, H=3. Window ending at index 7 has horizon [8, 9, 10] which captures the threat at 10!
    # Start index = 8 - 5 = 3
    t_seqs = gen.create_sequences(threat_obs)
    # Sequence at start_idx 3: window [3..7], horizon [8..10] -> contains t=10
    target_seq = next(s for s in t_seqs if s.horizonEndIndex >= 10 and s.horizonStartIndex <= 10)
    print(f"    Early-Warning Sequence Window: [{target_seq.startIndex}..{target_seq.endIndex}]")
    print(f"    Horizon Lookahead Range      : [{target_seq.horizonStartIndex}..{target_seq.horizonEndIndex}]")
    print(f"    Future Threat Binary Target  : {target_seq.futureThreatBinary}")
    print(f"    Future Threat Category       : {target_seq.futureThreatCategory}")

    assert target_seq.futureThreatBinary == 1
    assert target_seq.futureThreatCategory == "DOS_LIKE"
    print("    [PASS] Early-warning target successfully captured threat within horizon H.")

    # 4. Anti-Leakage Chronological Train/Test Split Audit
    print("\n[4/6] Auditing Temporal Anti-Leakage Train/Test Split...")
    stream_30 = [{"packet_rate": float(i * 10), "label": "NORMAL"} for i in range(30)]
    obs_30 = temporal_feature_engine.process_telemetry_stream(stream_30)
    train_seqs, test_seqs = gen.chronological_train_test_split(obs_30, train_ratio=0.60)
    # 30 * 0.60 = 18. Train obs: 0..17 (length 18). Buffer gap: 2. Test obs: 20..29 (length 10 >= 7)
    print(f"    Train Sequences Count: {len(train_seqs)}")
    print(f"    Test Sequences Count : {len(test_seqs)}")

    last_train = train_seqs[-1]
    first_test = test_seqs[0]
    print(f"    Max Train Target Horizon Index : {last_train.horizonEndIndex}")
    print(f"    Min Test Feature Start Index   : {first_test.startIndex}")

    # Critical Anti-Leakage Invariant: Train target horizon must not reach test features
    assert last_train.horizonEndIndex < first_test.startIndex
    print("    [PASS] Temporal non-inversion confirmed: Zero future test data leaks into train targets.")

    # 5. Defensive Edge Case Handling (Incomplete Window)
    print("\n[5/6] Auditing Defensive Incomplete Window Handling...")
    short_stream = [{"packet_rate": 10.0, "label": "NORMAL"} for _ in range(4)]  # 4 < T + H (7)
    short_obs = temporal_feature_engine.process_telemetry_stream(short_stream)
    short_seqs = gen.create_sequences(short_obs)
    assert len(short_seqs) == 0
    print("    [PASS] Incomplete stream correctly returned empty sequence set without crashing.")

    # 6. 3D Sequential Tensor Formatting & Metadata Persistence
    print("\n[6/6] Auditing 3D Tensor Generation and Dataset Builder...")
    dataset = sequence_dataset_builder.build_dataset(config=cfg)
    X_tr = dataset["X_train"]
    y_tr = dataset["y_train"]
    meta = dataset["metadata"]

    print(f"    X_train Tensor Shape: {X_tr.shape} (Expected: [N, 5, 16])")
    print(f"    y_train Tensor Shape: {y_tr.shape} (Expected: [N])")
    assert X_tr.ndim == 3
    assert X_tr.shape[1] == 5   # T = 5
    assert X_tr.shape[2] == 16  # D = 16
    assert len(y_tr) == X_tr.shape[0]

    meta_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "sequence_dataset_metadata.json"
    assert meta_file.exists()
    print("    [PASS] 3D sequential tensors formatted and metadata persisted.")

    print("\n" + "=" * 80)
    print("       ALL DAY 114 SLIDING WINDOWS TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day114_suite()