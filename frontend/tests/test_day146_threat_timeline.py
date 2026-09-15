import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.threats.threat_models import (
    DetectionSourceEnum, ThreatTimelineItem, ThreatFilterCriteria
)
from frontend.threats.threat_timeline_engine import threat_timeline_engine

def run_day146_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 146: THREAT TIMELINE & SECURITY EVENTS AUDIT")
    print("=" * 80 + "\n")

    threat_timeline_engine._seed_default_timeline()

    # 1. Timeline Chronological Ordering
    print("[1/9] Auditing Chronological Event Ordering (Most Recent First)...")
    timeline = threat_timeline_engine.get_timeline()
    cli_table = threat_timeline_engine.render_cli_timeline(timeline)
    print(cli_table)

    assert len(timeline) == 5
    timestamps = [e.timestamp for e in timeline]
    assert timestamps == sorted(timestamps, reverse=True)
    assert timeline[0].eventType == "EXFILTRATION_LIKE"
    assert timeline[-1].eventType == "DNS_ANOMALY"
    print("    [PASS] Chronological descending sequence verified.")

    # 2. Event Details Validation
    print("\n[2/9] Auditing Event Properties & Schema Fields...")
    e0 = timeline[0]
    print(f"    Event ID     : {e0.eventId}")
    print(f"    Timestamp    : {e0.timestamp}")
    print(f"    Event Type   : {e0.eventType}")
    print(f"    Flow         : {e0.sourceDevice} -> {e0.destinationDevice} ({e0.protocol}:{e0.destinationPort})")
    print(f"    Severity     : {e0.severity.value} (Risk: {e0.riskScore})")
    print(f"    Detector     : {e0.detectionSource.value} (Confidence: {e0.confidence*100:.0f}%)")

    assert e0.destinationDevice == "WEB-01"
    assert e0.severity == RiskLevelTier.CRITICAL
    assert e0.detectionSource == DetectionSourceEnum.ML
    print("    [PASS] Event payload matches schema specifications.")

    # 3. Severity Filtering
    print("\n[3/9] Auditing Event Filtering by Severity (CRITICAL)...")
    crit_events = threat_timeline_engine.get_timeline(ThreatFilterCriteria(severity=RiskLevelTier.CRITICAL))
    print(f"    Matched Critical Events: {[e.eventType for e in crit_events]}")
    assert len(crit_events) == 1
    assert crit_events[0].severity == RiskLevelTier.CRITICAL
    print("    [PASS] Severity filter verified.")

    # 4. Detection Source Filtering (SURICATA)
    print("\n[4/9] Auditing Event Filtering by Detector Source (SURICATA)...")
    suri_events = threat_timeline_engine.get_timeline(ThreatFilterCriteria(detectionSource=DetectionSourceEnum.SURICATA))
    print(f"    Matched Suricata Events: {[e.eventType for e in suri_events]}")
    assert len(suri_events) == 1
    assert suri_events[0].detectionSource == DetectionSourceEnum.SURICATA
    assert suri_events[0].eventType == "PORT_SCAN"
    print("    [PASS] Detection source filter verified.")

    # 5. Device-Specific Filtering
    print("\n[5/9] Auditing Event Filtering by Target Device ('DB-01')...")
    db_events = threat_timeline_engine.get_timeline(ThreatFilterCriteria(device="DB-01"))
    print(f"    Matched Events targeting DB-01: {[e.eventType for e in db_events]}")
    assert len(db_events) >= 1
    assert any("DB-01" in (e.sourceDevice, e.destinationDevice) for e in db_events)
    print("    [PASS] Device filter verified.")

    # 6. Unified Incident Drill-Down (Features -> Detection -> Risk -> ML -> XAI)
    print("\n[6/9] Auditing Unified Incident Drill-Down Investigation Synthesis...")
    drill = threat_timeline_engine.get_incident_drilldown("EVT-005-EXFIL")
    assert drill is not None

    print(f"    Incident ID    : {drill.drillDownId}")
    print(f"    Detector Info  : {drill.detectionDetails}")
    print(f"    Extracted Feat : {drill.extractedFeatures}")
    print(f"    Risk Context   : {drill.riskAssessment}")
    print(f"    XAI Narrative  : {drill.xaiExplanation}")
    print(f"    Recommended Act: {drill.recommendedContainment}")

    assert "packet_rate" in drill.extractedFeatures
    assert "Phase 15 SHAP" in drill.xaiExplanation
    assert "firewall rate-limiting" in drill.recommendedContainment
    print("    [PASS] Full 5-tier unified incident drill-down validated.")

    # 7. Duplicate Event Suppression
    print("\n[7/9] Auditing Duplicate Event Suppression...")
    count_before = len(threat_timeline_engine.events)
    dup_event = timeline[0].model_copy()
    threat_timeline_engine.ingest_event(dup_event)
    count_after = len(threat_timeline_engine.events)
    print(f"    Count Before: {count_before} | Count After Ingesting Duplicate: {count_after}")
    assert count_before == count_after
    print("    [PASS] Duplicate events suppressed.")

    # 8. Out-of-Order Ingestion Handling
    print("\n[8/9] Auditing Out-of-Order Event Chronological Insertion...")
    old_event = ThreatTimelineItem(
        eventId="EVT-HIST-000",
        timestamp="2026-09-15T09:30:00Z",  # Earlier than all existing events
        eventType="EARLY_PROBE",
        sourceDevice="CLIENT-01",
        destinationDevice="WEB-01",
        severity=RiskLevelTier.LOW,
        detectionSource=DetectionSourceEnum.ZEEK,
        confidence=0.85,
        riskScore=15.0
    )
    threat_timeline_engine.ingest_event(old_event)
    timeline_after = threat_timeline_engine.get_timeline()
    assert timeline_after[-1].eventId == "EVT-HIST-000"
    print(f"    Inserted event positioned at tail: {timeline_after[-1].timestamp}")
    print("    [PASS] Out-of-order events inserted into correct chronological position.")

    # 9. Missing / Invalid Timestamp Defensive Rejection
    print("\n[9/9] Auditing Defensive Validation of Invalid Timestamps...")
    invalid_caught = False
    try:
        ThreatTimelineItem(
            eventId="EVT-ERR",
            timestamp="NOT_A_TIMESTAMP",
            eventType="FAIL_TEST",
            sourceDevice="DEV-A",
            destinationDevice="DEV-B",
            severity=RiskLevelTier.LOW,
            detectionSource=DetectionSourceEnum.SIMULATION
        )
    except ValueError as e:
        invalid_caught = True
        print(f"    Trapped Malformed Timestamp: {e}")
    assert invalid_caught
    print("    [PASS] Malformed timestamp rejected defensively.")

    # Reset environment
    threat_timeline_engine._seed_default_timeline()

    print("\n" + "=" * 80)
    print("       ALL DAY 146 THREAT TIMELINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day146_suite()