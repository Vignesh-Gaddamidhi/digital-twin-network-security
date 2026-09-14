import sys
import json
import math
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import AssetCriticalityLevel
from services.digital_twin.risk.factors.asset.asset_criticality_models import (
    PredictionProvenance, ThreatAssetContextRecord
)
from services.digital_twin.risk.factors.asset.threat_asset_engine import threat_asset_engine

def run_day128_suite():
    print("=" * 80)
    print("       WEEK 19 - DAY 128: THREAT PROBABILITY & ASSET CRITICALITY AUDIT")
    print("=" * 80 + "\n")

    threat_asset_engine.clear()

    # 1. Valid Probability Ingress
    print("[1/8] Auditing Valid Threat Probability Ingress (0.0 -> 1.0)...")
    assert threat_asset_engine.validate_threat_probability(0.87) == 0.87
    assert threat_asset_engine.validate_threat_probability(0.0) == 0.0
    assert threat_asset_engine.validate_threat_probability(1.0) == 1.0
    print("    [PASS] Valid threat probability values accepted.")

    # 2. Defensive Rejection of Malformed Probabilities (-0.1, 1.5, NaN, Inf, null)
    print("\n[2/8] Auditing Defensive Rejection of Invalid Probabilities (-0.1, 1.5, NaN, Inf, null)...")
    invalid_inputs = [-0.1, 1.5, float("nan"), float("inf"), float("-inf"), None, "invalid_string"]
    for val in invalid_inputs:
        rejected = False
        try:
            threat_asset_engine.validate_threat_probability(val)
        except ValueError as exc:
            rejected = True
            print(f"    Rejected: {val!s:<14} -> Error: {exc}")
        assert rejected, f"Failed to reject invalid probability: {val}"
    print("    [PASS] All invalid threat probability types safely trapped and rejected.")

    # 3. Digital Twin Asset Criticality Lookup
    print("\n[3/8] Auditing Digital Twin Criticality Lookup for Standard Inventory...")
    expected_inventory = {
        "CLIENT-01": (AssetCriticalityLevel.LOW, 0.40),
        "DNS-SERVER-01": (AssetCriticalityLevel.MEDIUM, 0.60),
        "WEB-01": (AssetCriticalityLevel.HIGH, 0.80),
        "DB-01": (AssetCriticalityLevel.CRITICAL, 1.00),
        "CORE-ROUTER-01": (AssetCriticalityLevel.CRITICAL, 1.00)
    }

    for dev_id, (expected_level, expected_weight) in expected_inventory.items():
        asset = threat_asset_engine.get_asset(dev_id)
        crit = asset["assetCriticality"]
        weight = threat_asset_engine.criticality_configs[crit].score
        print(f"    Asset: {dev_id:<15} -> Criticality: {crit.value:<10} (Weight: {weight:.2f})")
        assert crit == expected_level
        assert weight == expected_weight

    print("    [PASS] Digital Twin asset criticality inventory validated.")

    # 4. Unknown & Missing Asset Error Handling
    print("\n[4/8] Auditing Error Handling on Missing & Unknown Assets...")
    unknown_caught = False
    try:
        threat_asset_engine.get_asset("NON-EXISTENT-ROUTER-99")
    except KeyError as exc:
        unknown_caught = True
        print(f"    Unknown Asset Caught : {exc}")
    assert unknown_caught

    blank_caught = False
    try:
        threat_asset_engine.get_asset("   ")
    except KeyError as exc:
        blank_caught = True
        print(f"    Blank Asset Caught   : {exc}")
    assert blank_caught
    print("    [PASS] Unknown and missing assets reliably raise KeyError.")

    # 5. Prediction Provenance Preservation
    print("\n[5/8] Auditing Prediction Lineage & Provenance Preservation...")
    prov = PredictionProvenance(
        predictionId="PRED-000123",
        modelName="RandomForest",
        modelVersion="1.0",
        featureVersion="feature-v1.0",
        datasetVersion="dataset-v1.0"
    )

    ctx_record = threat_asset_engine.bind_threat_to_asset(
        device_id="DB-01",
        threat_probability=0.87,
        prediction_provenance=prov
    )

    print(f"    Context Record ID  : {ctx_record.contextId}")
    print(f"    Bound Device ID    : {ctx_record.deviceId}")
    print(f"    Target Criticality : {ctx_record.assetCriticality.value} (Weight: {ctx_record.criticalityWeight})")
    print(f"    Bound Threat Prob  : {ctx_record.threatProbabilityFormatted}")
    print(f"    Preserved Model    : {ctx_record.provenance.modelName} (v: {ctx_record.provenance.modelVersion})")
    print(f"    Preserved Pred ID  : {ctx_record.provenance.predictionId}")

    assert ctx_record.provenance.predictionId == "PRED-000123"
    assert ctx_record.provenance.modelName == "RandomForest"
    assert ctx_record.provenance.modelVersion == "1.0"
    assert ctx_record.provenance.featureVersion == "feature-v1.0"
    print("    [PASS] Complete prediction provenance preserved.")

    # 6. Asset-Specific Risk Divergence Verification (CLIENT-01 vs DB-01)
    print("\n[6/8] Auditing Asset-Specific Risk Divergence (PORT_SCAN on CLIENT-01 vs DB-01)...")
    ctx_client = threat_asset_engine.bind_threat_to_asset("CLIENT-01", 0.87, prov)
    ctx_db = threat_asset_engine.bind_threat_to_asset("DB-01", 0.87, prov)

    print(f"    CLIENT-01 Context Base Risk : P(0.87) × C(0.40) = {ctx_client.baseContextScore:.4f} ({ctx_client.baseContextScoreFormatted})")
    print(f"    DB-01     Context Base Risk : P(0.87) × C(1.00) = {ctx_db.baseContextScore:.4f} ({ctx_db.baseContextScoreFormatted})")

    assert ctx_client.threatProbability == ctx_db.threatProbability
    assert ctx_db.baseContextScore > ctx_client.baseContextScore
    assert abs(ctx_client.baseContextScore - 0.3480) < 1e-3
    assert abs(ctx_db.baseContextScore - 0.8700) < 1e-3
    print("    [PASS] Asset-specific risk divergence proven: Critical asset receives 2.5x higher base context score.")

    # 7. Runtime Criticality Update Audit
    print("\n[7/8] Auditing Dynamic Runtime Asset Criticality Mutation...")
    print(f"    Original CLIENT-01 Criticality: {threat_asset_engine.get_asset('CLIENT-01')['assetCriticality'].value}")
    threat_asset_engine.update_asset_criticality("CLIENT-01", AssetCriticalityLevel.HIGH)
    updated_asset = threat_asset_engine.get_asset("CLIENT-01")
    print(f"    Updated CLIENT-01 Criticality : {updated_asset['assetCriticality'].value}")
    assert updated_asset["assetCriticality"] == AssetCriticalityLevel.HIGH

    ctx_recalc = threat_asset_engine.bind_threat_to_asset("CLIENT-01", 0.87, prov)
    print(f"    Recalculated Context Base Risk: P(0.87) × C(0.80) = {ctx_recalc.baseContextScore:.4f}")
    assert abs(ctx_recalc.baseContextScore - 0.6960) < 1e-3
    print("    [PASS] Runtime criticality mutation directly alters risk context score.")

    # 8. Visual Formatting & Artifact Persistence
    print("\n[8/8] Auditing Formatted Card Display & Persistence...")
    print(ctx_db.to_formatted_card())
    assert "THREAT + ASSET CONTEXT BINDING CARD" in ctx_db.to_formatted_card()

    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "asset_contexts.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 3
    assert stored[-1]["deviceId"] == "CLIENT-01"
    print(f"    Verified {len(stored)} persisted context records in asset_contexts.json.")
    print("    [PASS] Artifacts persisted and verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 128 THREAT + ASSET CRITICALITY TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day128_suite()