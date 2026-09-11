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
from services.digital_twin.security.pipeline.detection.detection_models import (
    DetectionTypeEnum, DetectionSeverityEnum
)
from services.digital_twin.security.pipeline.detection.detection_engine import pipeline_detection_engine
from services.digital_twin.security.pipeline.detection.baseline_store import baseline_store

def run_day89_suite():
    print("=" * 80)
    print("       WEEK 13 - DAY 89: DETECTION ENGINE AUDIT")
    print("=" * 80 + "\n")

    pipeline_detection_engine.clear()
    baseline_store.clear()

    # 1. Benign Traffic Detection
    print("[1/7] Auditing Benign Baseline Traffic Evaluation...")
    vec_benign = SecurityFeatureVector(
        vectorId="vec-b01",
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        packetRate=5.0,
        byteRate=2500.0,
        connectionRate=2.0,
        failedConnectionRatio=0.0,
        uniqueDestinationPorts=1
    )
    res_b = pipeline_detection_engine.detect(vec_benign)
    assert res_b.detected is False
    assert res_b.detectionType == DetectionTypeEnum.BENIGN
    assert res_b.confidence <= 0.2
    assert "within normal baseline" in res_b.summary
    print("    [PASS] Benign traffic evaluated cleanly without false alert.")

    # 2. Volumetric Traffic Spike Detection
    print("\n[2/7] Auditing Volumetric Traffic Spike (Z >= 3.0)...")
    vec_spike = SecurityFeatureVector(
        vectorId="vec-s01",
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        packetRate=150.0,
        byteRate=85000.0,  # Baseline is 2500 +/- 1000 -> Z = 82.5
        connectionRate=20.0
    )
    res_s = pipeline_detection_engine.detect(vec_spike)
    assert res_s.detected is True
    assert res_s.detectionType == DetectionTypeEnum.TRAFFIC_SPIKE
    assert res_s.confidence >= 0.85
    assert len(res_s.evidence) >= 1
    assert res_s.evidence[0].deviationScore >= 3.0
    assert "Potential suspicious behaviour detected" in res_s.summary
    print(f"    [PASS] TRAFFIC_SPIKE flagged: Confidence={res_s.confidence}, Z-Score={res_s.evidence[0].deviationScore}.")

    # 3. Port Reconnaissance / Anomaly Detection
    print("\n[3/7] Auditing Port Anomaly (Multi-Port Probing)...")
    vec_scan = SecurityFeatureVector(
        vectorId="vec-p01",
        targetDevice="WEB-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        uniqueDestinationPorts=7,
        portAttemptCount=7
    )
    res_p = pipeline_detection_engine.detect(vec_scan)
    assert res_p.detected is True
    assert res_p.detectionType == DetectionTypeEnum.PORT_ANOMALY
    assert res_p.evidence[0].observedValue == 7.0
    print(f"    [PASS] PORT_ANOMALY flagged: Observed {res_p.evidence[0].observedValue} unique ports probed.")

    # 4. Periodic C2 Beaconing Detection
    print("\n[4/7] Auditing Periodic C2 Beaconing (Low Jitter Variance <= 0.05s²)...")
    vec_beacon = SecurityFeatureVector(
        vectorId="vec-b01",
        targetDevice="SERVER-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_30S,
        windowDurationSeconds=30.0,
        connectionCount=10,
        averageInterval=1.0,
        intervalVariance=0.002  # Extremely low variance
    )
    res_beacon = pipeline_detection_engine.detect(vec_beacon)
    assert res_beacon.detected is True
    assert res_beacon.detectionType == DetectionTypeEnum.BEACONING_PATTERN
    assert res_beacon.confidence >= 0.90
    print(f"    [PASS] BEACONING_PATTERN flagged: Variance={vec_beacon.intervalVariance}s², Confidence={res_beacon.confidence}.")

    # 5. Outbound Volume Anomaly Detection (Data Exfiltration)
    print("\n[5/7] Auditing Outbound Volume Anomaly (Asymmetric Egress)...")
    vec_exfil = SecurityFeatureVector(
        vectorId="vec-e01",
        targetDevice="EXTERNAL-C2",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        outboundBytes=365000,
        inboundBytes=1200,
        bytesDirectionRatio=304.16
    )
    res_exfil = pipeline_detection_engine.detect(vec_exfil)
    assert res_exfil.detected is True
    assert res_exfil.detectionType == DetectionTypeEnum.OUTBOUND_VOLUME_ANOMALY
    assert res_exfil.severity == DetectionSeverityEnum.CRITICAL
    print(f"    [PASS] OUTBOUND_VOLUME_ANOMALY flagged: {vec_exfil.outboundBytes}B outbound, Severity={res_exfil.severity.value}.")

    # 6. Authentication Anomaly Detection
    print("\n[6/7] Auditing Authentication Anomaly (High Failed Ratio)...")
    vec_auth = SecurityFeatureVector(
        vectorId="vec-a01",
        targetDevice="SERVER-01",
        sourceDevice="CLIENT-01",
        window=FeatureWindowEnum.WINDOW_5S,
        windowDurationSeconds=5.0,
        connectionCount=10,
        failedConnectionCount=8,
        failedConnectionRatio=0.80
    )
    res_auth = pipeline_detection_engine.detect(vec_auth)
    assert res_auth.detected is True
    assert res_auth.detectionType == DetectionTypeEnum.AUTHENTICATION_ANOMALY
    assert res_auth.confidence >= 0.85
    print(f"    [PASS] AUTHENTICATION_ANOMALY flagged: {vec_auth.failedConnectionCount} failures ({vec_auth.failedConnectionRatio*100}%).")

    # 7. IDS Signature Match Passthrough
    print("\n[7/7] Auditing High-Fidelity IDS Alert Passthrough...")
    canon_alert = CanonicalEvent(
        eventTimestamp="2026-09-11T12:00:00Z",
        source="CLIENT-01",
        destination="WEB-01",
        protocol=CanonicalProtocolEnum.TCP,
        port=443,
        eventType="IDS_ALERT",
        severity=CanonicalSeverityEnum.CRITICAL,
        detectionSource=CanonicalDetectionSourceEnum.SURICATA,
        signature="ET EXPLOIT Log4j JNDI RCE"
    )
    res_ids = pipeline_detection_engine.detect(vec_benign, canon_alert)
    assert res_ids.detected is True
    assert res_ids.detectionType == DetectionTypeEnum.IDS_SIGNATURE_MATCH
    assert res_ids.confidence == 0.95
    assert "Log4j" in res_ids.evidence[0].reason
    print("    [PASS] High-fidelity IDS rule match converted to detection result.")

    print("\n" + "=" * 80)
    print("       ALL DAY 89 DETECTION ENGINE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day89_suite()