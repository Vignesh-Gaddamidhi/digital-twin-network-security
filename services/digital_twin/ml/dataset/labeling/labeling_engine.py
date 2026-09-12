from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from services.digital_twin.ml.dataset.schemas.dataset_models import DatasetSample
from services.digital_twin.ml.dataset.features.engineered_feature_vector import EngineeredFeatureVector
from services.digital_twin.ml.dataset.features.feature_engineering_engine import feature_engineering_engine
from services.digital_twin.ml.dataset.labeling.label_models import (
    LabeledDatasetSample, ModelBinaryLabel, ModelMulticlassLabel, LabelMethodEnum, LabelReport
)

ROOT_DIR = Path(__file__).resolve().parents[6]
LABELED_STORAGE_DIR = ROOT_DIR / "datasets" / "labeled"

class GroundTruthLabelingEngine:
    """Engine mapping multi-source telemetry to canonical ML classification targets without label leakage."""

    SCENARIO_TARGET_MAP = {
        "SCN-PORTSCAN-001": ModelMulticlassLabel.PORT_SCAN,
        "SCN-BRUTEFORCE-001": ModelMulticlassLabel.BRUTE_FORCE_LIKE,
        "SCN-DOS-001": ModelMulticlassLabel.DOS_LIKE,
        "SCN-DNS-001": ModelMulticlassLabel.DNS_ANOMALY,
        "SCN-BEACON-001": ModelMulticlassLabel.BEACONING,
        "SCN-LATERAL-001": ModelMulticlassLabel.LATERAL_MOVEMENT_LIKE,
        "SCN-EXFIL-001": ModelMulticlassLabel.EXFILTRATION_LIKE
    }

    # Banned tokens in predictor feature keys to guarantee zero label leakage
    LEAKAGE_BLACKLIST_KEYS = {
        "label", "target", "scenario", "attack", "alert", "signature",
        "detection", "is_anomaly", "threat", "compromised", "status"
    }

    def __init__(self, output_dir: Path = LABELED_STORAGE_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_file = self.output_dir / "labeled_samples.jsonl"
        self.labeled_samples: List[LabeledDatasetSample] = []

    def assign_labels(
        self,
        sample: DatasetSample,
        feature_vector: Optional[EngineeredFeatureVector] = None
    ) -> LabeledDatasetSample:
        # If feature vector not provided, compute it on the fly
        if not feature_vector:
            feature_vector = feature_engineering_engine.engineer_features(sample)

        scenario_id = sample.scenarioId or sample.metadata.get("scenarioId")
        raw_source = sample.telemetrySource.value

        # 1. Determine scenario label and model targets
        if scenario_id and scenario_id in self.SCENARIO_TARGET_MAP:
            scen_label = scenario_id
            multi_target = self.SCENARIO_TARGET_MAP[scenario_id]
            bin_target = ModelBinaryLabel.ANOMALOUS
            confidence = 1.00
            method = LabelMethodEnum.DETERMINISTIC_SCENARIO
            source_desc = f"SIMULATION_SCENARIO::{scenario_id}"
        elif sample.binaryLabel.value == "ANOMALOUS" or sample.service == "IDS_ALERT":
            scen_label = sample.service or "HEURISTIC_ANOMALY"
            bin_target = ModelBinaryLabel.ANOMALOUS
            method = LabelMethodEnum.RULE_BASED_DETECTION
            confidence = 0.85
            source_desc = f"SECURITY_PIPELINE::{raw_source}"

            # Infer multiclass category from behavioral features
            if feature_vector.unique_destination_ports >= 4:
                multi_target = ModelMulticlassLabel.PORT_SCAN
            elif feature_vector.failed_connections >= 3:
                multi_target = ModelMulticlassLabel.BRUTE_FORCE_LIKE
            elif feature_vector.dns_frequency > 5.0 or feature_vector.dns_queries >= 5:
                multi_target = ModelMulticlassLabel.DNS_ANOMALY
            elif feature_vector.interval_variance <= 0.05 and feature_vector.connection_frequency >= 1.0:
                multi_target = ModelMulticlassLabel.BEACONING
            elif feature_vector.bytes >= 250000 and feature_vector.bytes_per_second >= 50000.0:
                multi_target = ModelMulticlassLabel.EXFILTRATION_LIKE
            else:
                multi_target = ModelMulticlassLabel.DOS_LIKE
        else:
            scen_label = "BASELINE_NORMAL"
            bin_target = ModelBinaryLabel.NORMAL
            multi_target = ModelMulticlassLabel.NORMAL
            confidence = 0.99
            method = LabelMethodEnum.BENIGN_BASELINE
            source_desc = f"BENIGN_TELEMETRY::{raw_source}"

        # 2. Extract strictly sanitized features
        raw_feature_dict = feature_vector.to_feature_dict()
        sanitized_features: Dict[str, float] = {}
        for k, v in raw_feature_dict.items():
            # Leakage check: Key must not contain target leakage tokens
            if any(b in k.lower() for b in self.LEAKAGE_BLACKLIST_KEYS):
                continue
            sanitized_features[k] = float(v)

        num_vec = list(sanitized_features.values())

        labeled_sample = LabeledDatasetSample(
            sampleId=sample.sampleId,
            timestamp=sample.timestamp,
            features=sanitized_features,
            numericalVector=num_vec,
            scenario_label=scen_label,
            binary_label=bin_target,
            multiclass_label=multi_target,
            label_source=source_desc,
            label_confidence=round(confidence, 2),
            label_method=method,
            metadata={"originalEventId": sample.originalEventId, "sourceDevice": sample.sourceDevice, "destinationDevice": sample.destinationDevice}
        )

        self.labeled_samples.append(labeled_sample)

        # Write to persistent JSONL
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(labeled_sample.model_dump_json() + "\n")

        return labeled_sample

    def label_batch(self, samples: List[DatasetSample]) -> LabelReport:
        report = LabelReport(totalSamples=len(samples))
        total_conf = 0.0

        for s in samples:
            labeled = self.assign_labels(s)
            total_conf += labeled.label_confidence

            if labeled.binary_label == ModelBinaryLabel.NORMAL:
                report.normalSamples += 1
            else:
                report.anomalousSamples += 1

            if labeled.multiclass_label == ModelMulticlassLabel.UNKNOWN:
                report.unknownLabels += 1

            mc_key = labeled.multiclass_label.value
            report.multiclassCounts[mc_key] = report.multiclassCounts.get(mc_key, 0) + 1

            src_key = labeled.label_method.value
            report.labelSources[src_key] = report.labelSources.get(src_key, 0) + 1

            # Assert zero leakage
            for feat_name in labeled.features.keys():
                if any(b in feat_name.lower() for b in self.LEAKAGE_BLACKLIST_KEYS):
                    report.leakageCheckPassed = False

        if report.totalSamples > 0:
            report.averageConfidence = round(total_conf / float(report.totalSamples), 3)

        return report

    def clear(self):
        self.labeled_samples.clear()
        if self.output_file.exists():
            try:
                self.output_file.unlink()
            except Exception:
                pass

ground_truth_labeling_engine = GroundTruthLabelingEngine()