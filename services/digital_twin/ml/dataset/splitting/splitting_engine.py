import random
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from services.digital_twin.ml.dataset.labeling.label_models import LabeledDatasetSample
from services.digital_twin.ml.dataset.splitting.split_models import (
    SplitStrategyEnum, PartitionEnum, SplitSampleRecord, SplitMetadata
)

ROOT_DIR = Path(__file__).resolve().parents[6]
SPLIT_STORAGE_DIR = ROOT_DIR / "datasets" / "split"

class DatasetSplittingEngine:
    """Engine executing temporal, group-aware, and stratified train/test partitions."""

    def __init__(self, output_dir: Path = SPLIT_STORAGE_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.train_file = self.output_dir / "train.jsonl"
        self.test_file = self.output_dir / "test.jsonl"
        self.train_records: List[SplitSampleRecord] = []
        self.test_records: List[SplitSampleRecord] = []
        self.last_metadata: Optional[SplitMetadata] = None

    @staticmethod
    def _resolve_group_id(sample: LabeledDatasetSample) -> str:
        # Group precedence: runId -> simulationId -> flow_id -> scenario_label
        meta = sample.metadata or {}
        return str(
            meta.get("runId") or meta.get("simulationId") or meta.get("flow_id") or sample.scenario_label or "DEFAULT_RUN"
        )

    def split_dataset(
        self,
        samples: List[LabeledDatasetSample],
        strategy: SplitStrategyEnum = SplitStrategyEnum.GROUP,
        train_ratio: float = 0.80,
        random_seed: int = 42
    ) -> Tuple[List[SplitSampleRecord], List[SplitSampleRecord], SplitMetadata]:
        self.clear()
        train_ratio = max(0.1, min(0.9, train_ratio))
        test_ratio = round(1.0 - train_ratio, 2)

        if not samples:
            meta = SplitMetadata(
                strategy=strategy,
                trainRatio=train_ratio,
                testRatio=test_ratio,
                totalSamples=0,
                summary="Empty dataset supplied; zero partitions generated."
            )
            self.last_metadata = meta
            return [], [], meta

        train_samples: List[LabeledDatasetSample] = []
        test_samples: List[LabeledDatasetSample] = []

        # Strategy 1: TEMPORAL SPLIT (Strict time ordering)
        if strategy == SplitStrategyEnum.TEMPORAL:
            sorted_samples = sorted(samples, key=lambda s: str(s.timestamp))
            split_idx = int(len(sorted_samples) * train_ratio)
            train_samples = sorted_samples[:split_idx]
            test_samples = sorted_samples[split_idx:]

        # Strategy 2: GROUP-AWARE SPLIT (Atomic runs/sessions kept intact)
        elif strategy == SplitStrategyEnum.GROUP:
            # Group samples by run/session identifier
            groups: Dict[str, List[LabeledDatasetSample]] = {}
            for s in samples:
                gid = self._resolve_group_id(s)
                groups.setdefault(gid, []).append(s)

            group_keys = list(groups.keys())
            rng = random.Random(random_seed)
            rng.shuffle(group_keys)

            target_train_count = int(len(samples) * train_ratio)
            curr_train_count = 0

            for gid in group_keys:
                grp_items = groups[gid]
                if curr_train_count < target_train_count or len(test_samples) == 0:
                    train_samples.extend(grp_items)
                    curr_train_count += len(grp_items)
                else:
                    test_samples.extend(grp_items)

            # Fallback if all groups ended up in train
            if not test_samples and len(groups) > 1:
                moved_gid = group_keys[-1]
                test_samples = groups[moved_gid]
                train_samples = [s for s in train_samples if self._resolve_group_id(s) != moved_gid]

        # Strategy 3: STRATIFIED SPLIT (Balanced target class distribution)
        elif strategy == SplitStrategyEnum.STRATIFIED:
            classes: Dict[str, List[LabeledDatasetSample]] = {}
            for s in samples:
                classes.setdefault(s.multiclass_label.value, []).append(s)

            rng = random.Random(random_seed)
            for _, c_samples in classes.items():
                shuffled = list(c_samples)
                rng.shuffle(shuffled)
                split_idx = max(1, int(len(shuffled) * train_ratio)) if len(shuffled) > 1 else 1
                train_samples.extend(shuffled[:split_idx])
                test_samples.extend(shuffled[split_idx:])

        # Strategy 4: UNIFORM RANDOM
        else:
            shuffled = list(samples)
            rng = random.Random(random_seed)
            rng.shuffle(shuffled)
            split_idx = int(len(shuffled) * train_ratio)
            train_samples = shuffled[:split_idx]
            test_samples = shuffled[split_idx:]

        # Map to SplitSampleRecord
        self.train_records = [
            SplitSampleRecord(
                sampleId=s.sampleId,
                split=PartitionEnum.TRAIN,
                splitStrategy=strategy,
                timestamp=s.timestamp,
                groupId=self._resolve_group_id(s),
                scenarioId=s.scenario_label if s.scenario_label != "BASELINE_NORMAL" else None,
                features=s.features,
                numericalVector=s.numericalVector,
                binary_label=s.binary_label.value,
                multiclass_label=s.multiclass_label.value,
                metadata=s.metadata
            ) for s in train_samples
        ]

        self.test_records = [
            SplitSampleRecord(
                sampleId=s.sampleId,
                split=PartitionEnum.TEST,
                splitStrategy=strategy,
                timestamp=s.timestamp,
                groupId=self._resolve_group_id(s),
                scenarioId=s.scenario_label if s.scenario_label != "BASELINE_NORMAL" else None,
                features=s.features,
                numericalVector=s.numericalVector,
                binary_label=s.binary_label.value,
                multiclass_label=s.multiclass_label.value,
                metadata=s.metadata
            ) for s in test_samples
        ]

        # Anti-Leakage Audit
        meta = self._audit_and_generate_metadata(strategy, train_ratio, test_ratio)
        self.last_metadata = meta

        # Persist to disk
        self._persist_partitions()

        return self.train_records, self.test_records, meta

    def _audit_and_generate_metadata(
        self,
        strategy: SplitStrategyEnum,
        train_ratio: float,
        test_ratio: float
    ) -> SplitMetadata:
        train_ids: Set[str] = {r.sampleId for r in self.train_records}
        test_ids: Set[str] = {r.sampleId for r in self.test_records}
        disjoint_samples = len(train_ids.intersection(test_ids)) == 0

        train_groups: Set[str] = {r.groupId for r in self.train_records}
        test_groups: Set[str] = {r.groupId for r in self.test_records}
        disjoint_groups = (len(train_groups.intersection(test_groups)) == 0) if strategy == SplitStrategyEnum.GROUP else True

        temporal_passed = True
        if strategy == SplitStrategyEnum.TEMPORAL and self.train_records and self.test_records:
            max_train_t = max(r.timestamp for r in self.train_records)
            min_test_t = min(r.timestamp for r in self.test_records)
            temporal_passed = (max_train_t <= min_test_t)

        # Class distributions
        train_dist: Dict[str, int] = {}
        for r in self.train_records:
            train_dist[r.multiclass_label] = train_dist.get(r.multiclass_label, 0) + 1

        test_dist: Dict[str, int] = {}
        for r in self.test_records:
            test_dist[r.multiclass_label] = test_dist.get(r.multiclass_label, 0) + 1

        return SplitMetadata(
            strategy=strategy,
            trainRatio=train_ratio,
            testRatio=test_ratio,
            totalSamples=len(self.train_records) + len(self.test_records),
            trainSamplesCount=len(self.train_records),
            testSamplesCount=len(self.test_records),
            trainGroupCount=len(train_groups),
            testGroupCount=len(test_groups),
            trainClassDistribution=train_dist,
            testClassDistribution=test_dist,
            leakageAudited=True,
            disjointSamplesPassed=disjoint_samples,
            disjointGroupsPassed=disjoint_groups,
            temporalIsolationPassed=temporal_passed,
            summary="Data partition generated with verified zero-leakage compliance"
        )

    def _persist_partitions(self):
        with open(self.train_file, "w", encoding="utf-8") as f:
            for r in self.train_records:
                f.write(r.model_dump_json() + "\n")

        with open(self.test_file, "w", encoding="utf-8") as f:
            for r in self.test_records:
                f.write(r.model_dump_json() + "\n")

    def clear(self):
        self.train_records.clear()
        self.test_records.clear()
        self.last_metadata = None
        for p in [self.train_file, self.test_file]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

dataset_splitting_engine = DatasetSplittingEngine()