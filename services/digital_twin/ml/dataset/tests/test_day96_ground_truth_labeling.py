import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.dataset.schemas.dataset_models import (
    DatasetSample, BinaryLabelEnum, MulticlassLabelEnum, TelemetrySourceTypeEnum
)
from services.digital_twin.ml.dataset.labeling.label_models import (
    ModelBinaryLabel, ModelMulticlassLabel, LabelMethodEnum
)
from services.digital_twin.ml.dataset.labeling.labeling_engine import ground_truth_labeling_engine

def run_day96_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 96: GROUND-TRUTH LABELING & LEAKAGE AUDIT")
    print("=" * 80 + "\n")

    ground_truth_labeling_engine.clear()

    # 1. Baseline Normal Sample Labeling
    print("[1/6] Auditing Baseline Normal Traffic Labeling...")
    sample_normal = DatasetSample(
        sampleId="SMP-NORM-01",
        sourceDevice="CLIENT-01",
        destinationDevice="WEB-01",
        telemetrySource=TelemetrySourceTypeEnum.SIMULATION_TRAFFIC,
        protocol="TCP",
        destinationPort=443,
        service="HTTPS",
        bytes=1200,
        packets=4,
        flowDuration=0.5
    )
    labeled_normal = ground_truth_labeling_engine.assign_labels(sample_normal)

    assert labeled_normal.binary_label == ModelBinaryLabel.NORMAL
    assert labeled_normal.multiclass_label == ModelMulticlassLabel.NORMAL
    assert labeled_normal.scenario_label == "BASELINE_NORMAL"
    assert labeled_normal.label_confidence >= 0.95
    assert labeled_normal.label_method == LabelMethodEnum.BENIGN_BASELINE
    print("    [PASS] Normal sample mapped to NORMAL binary and multiclass target.")

    # 2. Phase 8 Reconnaissance Scenario (SCN-PORTSCAN-001)
    print("\n[2/6] Auditing SCN-PORTSCAN-001 Scenario Labeling...")
    sample_scan = DatasetSample(
        sampleId="SMP-SCAN-01",
        sourceDevice="CLIENT-01",
        destinationDevice="WEB-01",
        telemetrySource=TelemetrySourceTypeEnum.ATTACK_SCENARIO,
        protocol="TCP",
        destinationPort=8080,
        service="PORT_ACTIVITY",
        bytes=60,
        packets=1,
        flowDuration=0.01,
        scenarioId="SCN-PORTSCAN-001",
        uniquePorts=8
    )
    labeled_scan = ground_truth_labeling_engine.assign_labels(sample_scan)

    assert labeled_scan.binary_label == ModelBinaryLabel.ANOMALOUS
    assert labeled_scan.multiclass_label == ModelMulticlassLabel.PORT_SCAN
    assert labeled_scan.scenario_label == "SCN-PORTSCAN-001"
    assert labeled_scan.scenario_label != labeled_scan.multiclass_label.value
    assert labeled_scan.label_confidence == 1.00
    assert labeled_scan.label_method == LabelMethodEnum.DETERMINISTIC_SCENARIO
    print(f"    [PASS] Port scan labeled: scenario_label={labeled_scan.scenario_label} -> model_label={labeled_scan.multiclass_label.value} (Conf: {labeled_scan.label_confidence}).")

    # 3. Phase 8 DoS Saturation Scenario (SCN-DOS-001)
    print("\n[3/6] Auditing SCN-DOS-001 Scenario Labeling...")
    sample_dos = DatasetSample(
        sampleId="SMP-DOS-01",
        sourceDevice="CLIENT-01",
        destinationDevice="WEB-01",
        telemetrySource=TelemetrySourceTypeEnum.ATTACK_SCENARIO,
        protocol="TCP",
        destinationPort=80,
        service="HTTP",
        bytes=250000,
        packets=300,
        flowDuration=0.1,
        scenarioId="SCN-DOS-001"
    )
    labeled_dos = ground_truth_labeling_engine.assign_labels(sample_dos)
    assert labeled_dos.multiclass_label == ModelMulticlassLabel.DOS_LIKE
    assert labeled_dos.label_confidence == 1.00
    print("    [PASS] SCN-DOS-001 labeled as DOS_LIKE with 1.0 confidence.")

    # 4. Phase 8 Data Exfiltration Scenario (SCN-EXFIL-001)
    print("\n[4/6] Auditing SCN-EXFIL-001 Scenario Labeling...")
    sample_exfil = DatasetSample(
        sampleId="SMP-EXFIL-01",
        sourceDevice="CLIENT-01",
        destinationDevice="DB-01",
        telemetrySource=TelemetrySourceTypeEnum.ATTACK_SCENARIO,
        protocol="TCP",
        destinationPort=5432,
        service="HTTPS",
        bytes=450000,
        packets=350,
        flowDuration=0.5,
        scenarioId="SCN-EXFIL-001"
    )
    labeled_exfil = ground_truth_labeling_engine.assign_labels(sample_exfil)
    assert labeled_exfil.multiclass_label == ModelMulticlassLabel.EXFILTRATION_LIKE
    assert labeled_exfil.binary_label == ModelBinaryLabel.ANOMALOUS
    print("    [PASS] SCN-EXFIL-001 labeled as EXFILTRATION_LIKE.")

    # 5. Label Leakage Guardrail Audit
    print("\n[5/6] Auditing Feature Predictor Matrix X for Label Leakage...")
    feature_keys = labeled_scan.get_clean_feature_names()
    print(f"    Total Predictors in X: {len(feature_keys)}")
    print(f"    Sample Predictor Keys: {feature_keys[:6]}")

    banned_tokens = ["label", "target", "scenario", "attack", "alert", "threat", "signature"]
    for k in feature_keys:
        for b in banned_tokens:
            assert b not in k.lower(), f"Label leakage detected! Feature key '{k}' contains banned token '{b}'."

    assert "packet_rate" in feature_keys
    assert "port_80_ratio" in feature_keys
    assert "bytes_per_second" in feature_keys
    assert "scenario_label" not in feature_keys
    assert "multiclass_label" not in feature_keys
    print("    [PASS] Zero label leakage confirmed across all predictor columns in X.")

    # 6. Batch Labeling & Distribution Report Audit
    print("\n[6/6] Auditing Batch Label Report Generation...")
    batch = [sample_normal, sample_scan, sample_dos, sample_exfil]
    ground_truth_labeling_engine.clear()
    report = ground_truth_labeling_engine.label_batch(batch)

    print(f"    Total Samples       : {report.totalSamples}")
    print(f"    Normal Samples      : {report.normalSamples}")
    print(f"    Anomalous Samples   : {report.anomalousSamples}")
    print(f"    Average Confidence  : {report.averageConfidence}")
    print(f"    Multiclass Breakdown: {report.multiclassCounts}")
    print(f"    Leakage Check Passed: {report.leakageCheckPassed}")

    assert report.totalSamples == 4
    assert report.normalSamples == 1
    assert report.anomalousSamples == 3
    assert report.averageConfidence >= 0.98
    assert report.leakageCheckPassed is True
    assert report.multiclassCounts["NORMAL"] == 1
    assert report.multiclassCounts["PORT_SCAN"] == 1
    assert report.multiclassCounts["DOS_LIKE"] == 1
    assert report.multiclassCounts["EXFILTRATION_LIKE"] == 1
    print("    [PASS] Comprehensive LabelReport verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 96 GROUND-TRUTH LABELING TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day96_suite()