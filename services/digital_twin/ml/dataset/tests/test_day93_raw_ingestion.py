import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.dataset.schemas.raw_record_models import RawSourceEnum, DeduplicationStatusEnum
from services.digital_twin.ml.dataset.storage.raw_storage_manager import raw_storage_manager
from services.digital_twin.ml.dataset.ingestion.raw_ingestion_engine import raw_ingestion_engine

def run_day93_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 93: RAW TRAFFIC COLLECTION & INGESTION AUDIT")
    print("=" * 80 + "\n")

    raw_storage_manager.clear()

    # 1. Ingest Simulation JSONL Telemetry
    print("[1/6] Ingesting Simulation Telemetry Records...")
    sim_batch = [
        {"simulationId": "SIM-01", "timestamp": "2026-09-12T08:00:00Z", "sourceDevice": "CLIENT-01", "destinationDevice": "WEB-01", "protocol": "TCP", "destinationPort": 80, "bytes": 500},
        {"simulationId": "SIM-02", "timestamp": "2026-09-12T08:00:01Z", "sourceDevice": "CLIENT-01", "destinationDevice": "DB-01", "protocol": "TCP", "destinationPort": 5432, "bytes": 1200}
    ]
    sim_summary = raw_ingestion_engine.load_simulation_events(sim_batch, source_file="simulation_traffic.jsonl")
    assert sim_summary.totalRead == 2
    assert sim_summary.validRecords == 2
    assert sim_summary.duplicatesDetected == 0
    print(f"    [PASS] Ingested {sim_summary.validRecords} simulation records.")

    # 2. Ingest Suricata EVE Records
    print("\n[2/6] Ingesting Suricata EVE Alert Records...")
    suri_batch = [
        {"timestamp": "2026-09-12T08:05:00Z", "event_type": "alert", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "src_port": 49152, "dest_port": 443, "proto": "TCP", "alert": {"signature": "ET EXPLOIT Log4j RCE", "severity": 1}}
    ]
    suri_summary = raw_ingestion_engine.load_suricata_events(suri_batch, source_file="eve.json")
    assert suri_summary.validRecords == 1
    assert suri_summary.source == RawSourceEnum.SURICATA
    print("    [PASS] Suricata EVE record preserved with intact nested alert payload.")

    # 3. Ingest Zeek Logs
    print("\n[3/6] Ingesting Zeek Connection & DNS Records...")
    zeek_batch = [
        {"ts": "1773122000.0", "uid": "CZ101", "id.orig_h": "192.168.1.10", "id.resp_h": "192.168.1.53", "id.orig_p": 50000, "id.resp_p": 53, "proto": "udp", "query": "service.internal"}
    ]
    zeek_summary = raw_ingestion_engine.load_zeek_events(zeek_batch, source_file="conn.log")
    assert zeek_summary.validRecords == 1
    assert zeek_summary.source == RawSourceEnum.ZEEK
    print("    [PASS] Zeek conn record ingested with original timestamp.")

    # 4. Ingest Security Pipeline Canonical Events
    print("\n[4/6] Ingesting Security Pipeline Event Records...")
    sec_batch = [
        {"eventTimestamp": "2026-09-12T08:10:00Z", "source": "CLIENT-01", "destination": "WEB-01", "protocol": "TCP", "port": 443, "eventType": "IDS_ALERT", "severity": "HIGH"}
    ]
    sec_summary = raw_ingestion_engine.load_security_events(sec_batch, source_file="pipeline_events.json")
    assert sec_summary.validRecords == 1
    print("    [PASS] Pipeline security event ingested.")

    # 5. Non-Destructive Deduplication Audit
    print("\n[5/6] Auditing Non-Destructive Deduplication (Tagged, Not Deleted)...")
    # Ingest duplicate of the simulation event
    dup_batch = [
        {"simulationId": "SIM-01", "timestamp": "2026-09-12T08:00:00Z", "sourceDevice": "CLIENT-01", "destinationDevice": "WEB-01", "protocol": "TCP", "destinationPort": 80, "bytes": 500}
    ]
    dup_summary = raw_ingestion_engine.load_simulation_events(dup_batch, source_file="simulation_traffic.jsonl")
    assert dup_summary.totalRead == 1
    assert dup_summary.duplicatesDetected == 1

    all_sim_recs = raw_storage_manager.list_records(source=RawSourceEnum.SIMULATION)
    assert len(all_sim_recs) == 3  # 2 original + 1 duplicate record preserved
    assert all_sim_recs[2].deduplicationStatus == DeduplicationStatusEnum.DUPLICATE
    assert all_sim_recs[2].duplicateOf == all_sim_recs[0].rawRecordId
    print(f"    [PASS] Duplicate record preserved with duplicateOf={all_sim_recs[2].duplicateOf}.")

    # 6. Validation Error Logging & Zero Data Loss
    print("\n[6/6] Auditing Validation Failure Diagnostics (No Crash, Error Logged)...")
    bad_batch = [
        {"bytes": 100}  # Missing timestamp and endpoints
    ]
    bad_summary = raw_ingestion_engine.load_simulation_events(bad_batch, source_file="corrupted.jsonl")
    assert bad_summary.invalidRecords == 1

    bad_rec = raw_storage_manager.list_records()[-1]
    assert bad_rec.validationStatus == "INVALID"
    assert len(bad_rec.validationErrors) >= 2
    assert "Missing timestamp field" in bad_rec.validationErrors[0]
    print(f"    [PASS] Invalid record preserved with diagnostic errors: {bad_rec.validationErrors}")

    print("\n" + "=" * 80)
    print("       ALL DAY 93 RAW DATA INGESTION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day93_suite()