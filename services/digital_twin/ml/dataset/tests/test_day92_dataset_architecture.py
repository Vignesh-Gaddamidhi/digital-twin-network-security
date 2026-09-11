import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.security.pipeline.normalization.canonical_event import (
    CanonicalEvent, CanonicalDetectionSourceEnum, CanonicalProtocolEnum, CanonicalSeverityEnum
)
from services.digital_twin.security.pipeline.features.feature_definitions import (
    SecurityFeatureVector, FeatureWindowEnum
)
from services.digital_twin.ml.dataset.schemas.dataset_models import (
    BinaryLabelEnum, MulticlassLabelEnum, TelemetrySourceTypeEnum, DatasetSample
)
from services.digital_twin.ml.dataset.inventory.source_inventory import (
    SourceInventoryAdapter, dataset_inventory
)

def run_day92_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 92: ML DATASET ARCHITECTURE & DATA SOURCES AUDIT")
    print("=" * 80 + "\n")

    dataset_inventory.clear()

    # 1. Normal Traffic Sample Ingestion (Zeek / Simulation)
    print("[1/5] Ingesting Baseline Normal Traffic Sample...")
    canon_normal = CanonicalEvent(
        eventTimestamp="2026-09-11T12:00:00Z",
        source="CLIENT-01",
        destination="WEB-01",
        protocol=CanonicalProtocolEnum.TCP,
        port=80,
        eventType="HTTP_REQUEST",
        severity=CanonicalSeverityEnum.INFO,
        detectionSource=CanonicalDetectionSourceEnum.ZEEK,
        bytes=1200,
        packets=6
    )
    vec_normal = SecurityFeatureVector(
        vectorId="vec-n01",
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        packetRate=1.2,
        byteRate=240.0,
        connectionRate=1.0,
        uniqueDestinationPorts=1
    )

    sample_normal = SourceInventoryAdapter.from_canonical_event(canon_normal, vec_normal)
    dataset_inventory.add_sample(sample_normal)

    assert sample_normal.binaryLabel == BinaryLabelEnum.NORMAL
    assert sample_normal.multiclassLabel == MulticlassLabelEnum.NORMAL
    assert sample_normal.telemetrySource == TelemetrySourceTypeEnum.ZEEK_NSM
    print("    [PASS] Baseline normal sample generated with NORMAL labels.")

    # 2. Attack Scenario Ingestion (SCN-PORTSCAN-001)
    print("\n[2/5] Ingesting Phase 8 Reconnaissance Scenario Sample (SCN-PORTSCAN-001)...")
    canon_scan = CanonicalEvent(
        eventTimestamp="2026-09-11T12:00:05Z",
        source="CLIENT-01",
        destination="WEB-01",
        protocol=CanonicalProtocolEnum.TCP,
        port=8080,
        eventType="PORT_ACTIVITY",
        severity=CanonicalSeverityEnum.MEDIUM,
        detectionSource=CanonicalDetectionSourceEnum.SURICATA,
        bytes=60,
        packets=1
    )
    vec_scan = SecurityFeatureVector(
        vectorId="vec-p01",
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        packetRate=7.0,
        byteRate=420.0,
        uniqueDestinationPorts=7,
        failedConnectionCount=6
    )

    sample_scan = SourceInventoryAdapter.from_canonical_event(canon_scan, vec_scan, scenario_id="SCN-PORTSCAN-001")
    dataset_inventory.add_sample(sample_scan)

    assert sample_scan.binaryLabel == BinaryLabelEnum.ANOMALOUS
    assert sample_scan.multiclassLabel == MulticlassLabelEnum.PORT_SCAN
    assert sample_scan.telemetrySource == TelemetrySourceTypeEnum.ATTACK_SCENARIO
    assert sample_scan.uniquePorts == 7
    print(f"    [PASS] Port scan sample labeled: binary={sample_scan.binaryLabel.value}, multi={sample_scan.multiclassLabel.value}.")

    # 3. Data Exfiltration Scenario Sample (SCN-EXFIL-001)
    print("\n[3/5] Ingesting Phase 8 Data Exfiltration Scenario Sample (SCN-EXFIL-001)...")
    canon_exfil = CanonicalEvent(
        eventTimestamp="2026-09-11T12:00:10Z",
        source="CLIENT-01",
        destination="DB-01",
        protocol=CanonicalProtocolEnum.TCP,
        port=5432,
        eventType="HTTPS_CONNECTION",
        severity=CanonicalSeverityEnum.CRITICAL,
        detectionSource=CanonicalDetectionSourceEnum.SIMULATION,
        bytes=450000,
        packets=350,
        metadata={"direction": "OUTBOUND"}
    )
    vec_exfil = SecurityFeatureVector(
        vectorId="vec-e01",
        targetDevice="DB-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        packetRate=70.0,
        byteRate=90000.0,
        outboundBytes=450000,
        bytesDirectionRatio=450000.0
    )

    sample_exfil = SourceInventoryAdapter.from_canonical_event(canon_exfil, vec_exfil, scenario_id="SCN-EXFIL-001")
    dataset_inventory.add_sample(sample_exfil)

    assert sample_exfil.binaryLabel == BinaryLabelEnum.ANOMALOUS
    assert sample_exfil.multiclassLabel == MulticlassLabelEnum.DATA_EXFILTRATION
    assert sample_exfil.bytes == 450000
    print("    [PASS] Exfiltration sample labeled with DATA_EXFILTRATION.")

    # 4. Feature vs Metadata Separation Audit (No Leakage)
    print("\n[4/5] Auditing Feature vs Metadata Separation (to_feature_dict)...")
    feat_dict = sample_exfil.to_feature_dict()
    print(f"    Extracted Features Count: {len(feat_dict)}")
    print(f"    Sample Feature Keys: {list(feat_dict.keys())[:6]}")

    # Invariant: Leakable identifiers must NOT be features
    assert "sampleId" not in feat_dict
    assert "sourceDevice" not in feat_dict
    assert "destinationDevice" not in feat_dict
    assert "originalEventId" not in feat_dict
    assert "binaryLabel" not in feat_dict
    assert "multiclassLabel" not in feat_dict
    assert "byteRate" in feat_dict
    assert "bytesDirectionRatio" in feat_dict
    print("    [PASS] Entity metadata and ground truth labels are strictly isolated from features.")

    # 5. Dataset Metadata Provenance & Class Distribution
    print("\n[5/5] Auditing Dataset Metadata Provenance & Distributions...")
    meta = dataset_inventory.generate_metadata(version="1.0.0")

    print(f"    Total Samples       : {meta.totalSamples}")
    print(f"    Normal Samples      : {meta.normalSamples}")
    print(f"    Anomalous Samples   : {meta.anomalousSamples}")
    print(f"    Multiclass Breakdown: {meta.multiclassCounts}")
    print(f"    Source Types        : {[s.value for s in meta.sourceTypes]}")

    assert meta.totalSamples == 3
    assert meta.normalSamples == 1
    assert meta.anomalousSamples == 2
    assert meta.multiclassCounts["NORMAL"] == 1
    assert meta.multiclassCounts["PORT_SCAN"] == 1
    assert meta.multiclassCounts["DATA_EXFILTRATION"] == 1
    assert TelemetrySourceTypeEnum.ATTACK_SCENARIO in meta.sourceTypes
    print("    [PASS] Dataset metadata correctly aggregates class balance and provenance.")

    print("\n" + "=" * 80)
    print("       ALL DAY 92 ML DATASET ARCHITECTURE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day92_suite()