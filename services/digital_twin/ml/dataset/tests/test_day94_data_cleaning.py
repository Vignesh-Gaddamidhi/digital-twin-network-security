import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.dataset.schemas.raw_record_models import RawRecord, RawSourceEnum
from services.digital_twin.ml.dataset.cleaning.cleaning_engine import data_cleaning_engine
from services.digital_twin.ml.dataset.cleaning.cleaning_models import CleaningReport

def run_day94_suite():
    print("=" * 80)
    print("       WEEK 14 - DAY 94: DATA CLEANING & PREPROCESSING ENGINE AUDIT")
    print("=" * 80 + "\n")

    data_cleaning_engine.clear()
    report = CleaningReport()

    # 1. Type Normalization & Feature-Specific Imputation
    print("[1/5] Auditing Type Normalization & Missing Value Imputation...")
    raw_impute = RawRecord(
        source=RawSourceEnum.ZEEK,
        fingerprint="fp-001",
        rawPayload={
            "timestamp": "2026-09-12T10:00:00Z",
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "192.168.1.20",
            "id.resp_p": "80",          # String port -> 80
            "proto": "tcp",              # Lowercase proto -> TCP
            "orig_bytes": "1500"         # String bytes -> 1500
            # Missing duration, missing packets, missing service
        }
    )
    sample_clean = data_cleaning_engine.clean_record(raw_impute, report)
    assert sample_clean is not None
    assert sample_clean.protocol == "TCP"
    assert sample_clean.destinationPort == 80
    assert sample_clean.bytes == 1500
    assert sample_clean.packets == 1              # Default minimum packet
    assert sample_clean.flowDuration == 0.001     # Default minimum duration
    assert sample_clean.service == "HTTP"         # Inferred from port 80
    print("    [PASS] Type conversion ('80'->80, 'tcp'->TCP) and service inference (80->HTTP) verified.")

    # 2. Invalid Value Detection & Rejection
    print("\n[2/5] Auditing Invalid Value Detection & Rejection...")
    # Negative bytes
    raw_neg = RawRecord(
        source=RawSourceEnum.SIMULATION,
        fingerprint="fp-002",
        rawPayload={"timestamp": "2026-09-12T10:00:01Z", "source": "CLIENT-01", "destination": "WEB-01", "bytes": -500}
    )
    res_neg = data_cleaning_engine.clean_record(raw_neg, report)
    assert res_neg is None

    # Illegal port
    raw_badport = RawRecord(
        source=RawSourceEnum.SURICATA,
        fingerprint="fp-003",
        rawPayload={"timestamp": "2026-09-12T10:00:02Z", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "dest_port": 99999}
    )
    res_badport = data_cleaning_engine.clean_record(raw_badport, report)
    assert res_badport is None

    # Missing destination endpoint
    raw_no_dst = RawRecord(
        source=RawSourceEnum.SIMULATION,
        fingerprint="fp-004",
        rawPayload={"timestamp": "2026-09-12T10:00:03Z", "source": "CLIENT-01"}
    )
    res_no_dst = data_cleaning_engine.clean_record(raw_no_dst, report)
    assert res_no_dst is None
    print("    [PASS] Rejected negative bytes, port 99999, and missing endpoints with audit logs.")

    # 3. Legitimate Attack Outlier Preservation
    print("\n[3/5] Auditing Legitimate Attack Outlier Preservation (Zero Inappropriate Pruning)...")
    raw_outlier = RawRecord(
        source=RawSourceEnum.SIMULATION,
        fingerprint="fp-005",
        rawPayload={
            "timestamp": "2026-09-12T10:00:04Z",
            "sourceDevice": "CLIENT-01",
            "destinationDevice": "DB-01",
            "destinationPort": 5432,
            "protocol": "TCP",
            "bytes": 450000,             # Massive legitimate exfiltration volume
            "packets": 350,
            "duration": 0.5,
            "scenarioId": "SCN-EXFIL-001"
        }
    )
    res_outlier = data_cleaning_engine.clean_record(raw_outlier, report)
    assert res_outlier is not None
    assert res_outlier.bytes == 450000
    assert res_outlier.multiclassLabel.value == "DATA_EXFILTRATION"
    assert res_outlier.byteRate == 900000.0
    print("    [PASS] Massive exfiltration outlier preserved without truncation.")

    # 4. Duplicate Record Handling
    print("\n[4/5] Auditing Duplicate Record Propagation Tracking...")
    raw_dup = RawRecord(
        source=RawSourceEnum.ZEEK,
        fingerprint="fp-001",
        deduplicationStatus="DUPLICATE",
        duplicateOf="RAW-001",
        rawPayload={
            "timestamp": "2026-09-12T10:00:00Z",
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "192.168.1.20",
            "id.resp_p": 80
        }
    )
    res_dup = data_cleaning_engine.clean_record(raw_dup, report)
    assert res_dup is not None
    assert report.duplicatesHandled >= 1
    print("    [PASS] Duplicate record propagated and counted in report.")

    # 5. Cleaning Report Metrics Audit
    print("\n[5/5] Auditing Cleaning Report Diagnostics...")
    print(f"    Total Processed : {report.totalRecords}")
    print(f"    Valid Records   : {report.validRecords}")
    print(f"    Invalid Records : {report.invalidRecords}")
    print(f"    Corrections     : {report.correctedValuesCount}")
    print(f"    Rejections      : {report.rejectedRecordsCount}")

    assert report.totalRecords == 6
    assert report.validRecords == 3
    assert report.invalidRecords == 3
    assert report.rejectedRecordsCount == 3
    assert len(report.rejections) == 3
    assert len(report.corrections) >= 3
    print("    [PASS] Cleaning report populated with full diagnostic lineage.")

    print("\n" + "=" * 80)
    print("       ALL DAY 94 DATA CLEANING TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day94_suite()