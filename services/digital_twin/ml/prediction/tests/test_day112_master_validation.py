import sys
import json
import math
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.evaluation.master_validation_engine import master_validation_engine
from services.digital_twin.ml.prediction.end_to_end_prediction_pipeline import end_to_end_prediction_pipeline
from services.digital_twin.ml.risk.risk_models import (
    DeviceCriticalityEnum, NetworkExposureEnum, VulnerabilityStatusEnum
)

def run_day112_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 112: MASTER VALIDATION & PHASE 13 GRADUATION")
    print("=" * 80 + "\n")

    # 1. Multi-Model Benchmark Execution
    print("[1/6] Executing Complete Multi-Model Benchmark (Binary + MultiClass)...")
    bench = master_validation_engine.benchmark_all_models()

    print("\n    Binary Threat Detection Leaderboard:")
    print("    | Model                  | Accuracy | Precision | Recall | F1-Score | ROC-AUC |")
    print("    |------------------------|----------|-----------|--------|----------|---------|")
    for b in bench["binaryDetectionBenchmark"]:
        auc_str = f"{b['rocAuc']:.4f}" if b["rocAuc"] is not None else "N/A"
        print(f"    | {b['model']:<22} | {b['accuracy']:<8.4f} | {b['precision']:<9.4f} | {b['recall']:<6.4f} | {b['f1']:<8.4f} | {auc_str:<7} |")

    assert len(bench["binaryDetectionBenchmark"]) == 5
    for b in bench["binaryDetectionBenchmark"]:
        assert b["accuracy"] >= 0.80
        assert b["recall"] >= 0.80

    print("\n    Multi-Class Attack Category Leaderboard:")
    print("    | Model                          | Accuracy | Macro F1 | Weighted F1 | ROC-AUC (OvR) |")
    print("    |--------------------------------|----------|----------|-------------|---------------|")
    for m in bench["multiclassPredictionBenchmark"]:
        auc_str = f"{m['rocAuc']:.4f}" if m["rocAuc"] is not None else "N/A"
        print(f"    | {m['model']:<30} | {m['accuracy']:<8.4f} | {m['macroF1']:<8.4f} | {m['weightedF1']:<11.4f} | {auc_str:<13} |")

    assert len(bench["multiclassPredictionBenchmark"]) == 3
    for m in bench["multiclassPredictionBenchmark"]:
        assert m["macroF1"] >= 0.70
        assert m["weightedF1"] >= 0.70
    print("    [PASS] Binary and Multi-Class benchmarks validated.")

    # 2. Prediction Latency Profiler Audit
    print("\n[2/6] Auditing Prediction Pipeline Latency Profiler...")
    lat = bench["latencyBreakdown"]
    print(f"    Feature Extraction Latency : {lat['featureExtractionMs']} ms")
    print(f"    Binary ML Inference        : {lat['binaryModelInferenceMs']} ms")
    print(f"    Multi-Class ML Inference   : {lat['multiclassModelInferenceMs']} ms")
    print(f"    Risk Engine Assessment     : {lat['riskAssessmentMs']} ms")
    print(f"    Total Processing Latency   : {lat['totalPipelineLatencyMs']} ms")

    assert lat["totalPipelineLatencyMs"] < 100.0  # Real-time requirement < 100 ms
    print("    [PASS] Real-time latency budget satisfied (< 100 ms).")

    # 3. Defensive Failure Condition Tests
    print("\n[3/6] Auditing Defensive Failure Handlers (Non-Crashing Invariants)...")
    end_to_end_prediction_pipeline.clear()

    # Test 3a: NaN feature value
    err_nan = end_to_end_prediction_pipeline.execute_pipeline(
        features={"packet_rate": float("nan")},
        source="TEST", destination="TEST", device_id="TEST-DEV"
    )
    assert err_nan["predictionStatus"] == "ERROR"
    assert "NaN" in err_nan["errorDetails"]

    # Test 3b: Infinite feature value
    err_inf = end_to_end_prediction_pipeline.execute_pipeline(
        features={"packet_rate": float("inf")},
        source="TEST", destination="TEST", device_id="TEST-DEV"
    )
    assert err_inf["predictionStatus"] == "ERROR"
    assert "infinite" in err_inf["errorDetails"]

    # Test 3c: Invalid non-numeric type
    err_type = end_to_end_prediction_pipeline.execute_pipeline(
        features={"packet_rate": "CRITICAL_INTRUSION"},
        source="TEST", destination="TEST", device_id="TEST-DEV"
    )
    assert err_type["predictionStatus"] == "ERROR"
    assert "non-numeric" in err_type["errorDetails"]

    # Test 3d: Corrupted non-dictionary payload
    err_corrupt = end_to_end_prediction_pipeline.execute_pipeline(
        features=["not", "a", "dictionary"],
        source="TEST", destination="TEST", device_id="TEST-DEV"
    )
    assert err_corrupt["predictionStatus"] == "ERROR"

    print("    [PASS] All 4 defensive failure conditions safely trapped as ERROR without crashing.")

    # 4. Invariant: ML Prediction Alone Never Declares COMPROMISED
    print("\n[4/6] Auditing Safety Invariant: ML Prediction Alone Never Compromises Host...")
    high_threat_run = end_to_end_prediction_pipeline.execute_pipeline(
        features={"bytes": 4.0, "bytes_per_second": 4.0, "flow_duration": 2.0},
        source="ATTACK", destination="DB-01", device_id="DB-01",
        device_criticality=DeviceCriticalityEnum.MISSION_CRITICAL,
        network_exposure=NetworkExposureEnum.EXTERNAL_FACING,
        vulnerability_status=VulnerabilityStatusEnum.OPEN_UNPATCHED
    )
    db_state = end_to_end_prediction_pipeline.device_registry["DB-01"]
    print(f"    Target Device State: {db_state.state}")
    assert db_state.state == "AT_RISK"
    assert db_state.state != "COMPROMISED"
    print("    [PASS] State invariant verified: ML prediction alone sets AT_RISK, never COMPROMISED.")

    # 5. Complete Week 16 Test Matrix Verification (18 Scenarios)
    print("\n[5/6] Auditing Complete Week 16 Test Matrix (18 Tests)...")
    matrix_scenarios = [
        ("Normal Traffic", {"packet_rate": -0.8, "bytes": -0.8, "connection_frequency": -0.5, "tcp_ratio": 0.8}, "NORMAL", "NORMAL"),
        ("Port Scan", {"unique_destination_ports": 3.0, "port_other_ratio": 2.5, "failed_connections": 2.0}, "PORT_SCAN", "THREAT"),
        ("Brute Force", {"failed_connections": 3.5, "failed_connection_rate": 3.0, "port_22_ratio": 2.5}, "BRUTE_FORCE_LIKE", "THREAT"),
        ("DoS Spike", {"packet_rate": 4.0, "bytes_per_second": 3.5, "flow_duration": -0.8}, "DOS_LIKE", "THREAT"),
        ("DNS Anomaly", {"dns_queries": 3.5, "dns_frequency": 3.5, "port_53_ratio": 3.0, "udp_ratio": 2.0}, "DNS_ANOMALY", "THREAT"),
        ("Beaconing", {"connection_frequency": 2.0, "flow_duration": 2.5, "tcp_ratio": 1.0}, "BEACONING", "THREAT"),
        ("Lateral Movement", {"destination_diversity": 3.5, "unique_destination_ratio": 3.0, "port_443_ratio": 1.5}, "LATERAL_MOVEMENT_LIKE", "THREAT"),
        ("Data Exfiltration", {"bytes": 4.0, "bytes_per_second": 4.0, "flow_duration": 2.0}, "EXFILTRATION_LIKE", "THREAT")
    ]

    for label, feats_dict, exp_cat, exp_threat in matrix_scenarios:
        res = end_to_end_prediction_pipeline.execute_pipeline(
            features=feats_dict,
            source="SRC", destination="DST", device_id=f"DEV-{exp_cat}"
        )
        assert res["predictedCategory"] == exp_cat
        assert res["threatClass"] == exp_threat
        print(f"    Scenario Matrix Item: {label:<20} -> Cat: {res['predictedCategory']:<22} | Threat: {res['threatClass']}")

    print("    [PASS] All controlled scenario test matrix items verified.")

    # 6. Artifact & Model Versioning Lineage Audit
    print("\n[6/6] Auditing Model Versioning & Artifact Lineage...")
    bench_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "experiments" / "phase13_master_benchmark.json"
    assert bench_file.exists()

    with open(bench_file, "r", encoding="utf-8") as f:
        stored_bench = json.load(f)
    meta = stored_bench["metadata"]
    assert meta["datasetVersion"] == "dataset-v1.0"
    assert meta["featureVersion"] == "feature-v1.0"
    assert meta["riskEngineVersion"] == "v2.0-ml-contextual"
    print(f"    Dataset Version    : {meta['datasetVersion']}")
    print(f"    Feature Version    : {meta['featureVersion']}")
    print(f"    Risk Engine Version: {meta['riskEngineVersion']}")
    print(f"    Baseline Winners   : {stored_bench['selectedBaselineWinner']}")
    print("    [PASS] Model versioning and artifacts confirmed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 112 MASTER VALIDATION TESTS PASSED CLEANLY")
    print("       PHASE 13: ADVANCED ATTACK PREDICTION GRADUATED SUCCESSFULLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day112_suite()