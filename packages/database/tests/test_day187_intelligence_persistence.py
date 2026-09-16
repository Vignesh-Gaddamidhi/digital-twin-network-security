import sys
import asyncio
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.twin_persistence_repository import twin_persistence_repo
from packages.database.src.soc_intelligence_repository import soc_intelligence_repo
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

async def run_day187_suite():
    print("=" * 80)
    print("       WEEK 27 - DAY 187: SOC INTELLIGENCE & INVESTIGATION CHAIN AUDIT")
    print("================================================================================\n")

    await db_manager.connect()
    prisma = db_manager.client

    # 1. Seed Network Twin Devices for Foreign-Key Integrity
    print("[1/7] Seeding Baseline Devices (CLIENT-01, WEB-01, DB-01)...")
    c1 = NetworkDeviceModel(id="CLIENT-01", name="client-01.corp", hostname="client-01.corp", device_type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL, ipAddresses=["10.0.1.25"])
    w1 = NetworkDeviceModel(id="WEB-01", name="web-01.dmz", hostname="web-01.dmz", device_type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ipAddresses=["10.0.2.99"])
    d1 = NetworkDeviceModel(id="DB-01", name="db-01.internal", hostname="db-01.internal", device_type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DATABASE, ipAddresses=["10.0.3.10"])
    
    await twin_persistence_repo.persist_device_aggregate(c1)
    await twin_persistence_repo.persist_device_aggregate(w1)
    await twin_persistence_repo.persist_device_aggregate(d1)
    print("    [PASS] 3 devices seeded.")

    # 2. Correlated Incident Creation
    print("\n[2/7] Auditing Incident Record Creation...")
    inc = await soc_intelligence_repo.create_or_update_incident(
        incident_id="INC-2026-0916-001",
        title="Critical Lateral Movement: Infiltration from Corp Client to DB Tier",
        severity="CRITICAL",
        status="INVESTIGATING",
        description="CVE-2026-RCE exploit on WEB-01 followed by unauthorized port 3306 queries toward DB-01.",
        assigned_operator="SOC_SENIOR_ANALYST"
    )
    assert inc.incidentId == "INC-2026-0916-001"
    print(f"    Incident ID        : {inc.incidentId}")
    print(f"    Assigned Operator  : {inc.assignedOperator}")
    print("    [PASS] Incident record persisted.")

    # 3. Alert Lifecycle & Incident Association
    print("\n[3/7] Auditing Alert Lifecycle & Statuses...")
    alt = await soc_intelligence_repo.create_or_update_alert(
        alert_id="ALT-20260916-001",
        source="10.0.1.25:52110",
        destination="10.0.2.99:80",
        event_type="SQL_INJECTION_PROBE",
        affected_device_id="WEB-01",
        severity="CRITICAL",
        detection_source="SURICATA",
        detection_type="SIGNATURE_MATCH",
        confidence=0.99,
        risk_score=85.0,
        risk_level="CRITICAL",
        status="INVESTIGATING",
        evidence="Payload 'UNION SELECT 1, @@version' in URI parameters",
        incident_id=inc.incidentId
    )
    assert alt.alertId == "ALT-20260916-001"
    assert alt.status == "INVESTIGATING"
    print(f"    Alert ID           : {alt.alertId} ({alt.status})")
    print(f"    Affected Device    : {alt.affectedDeviceId}")
    print("    [PASS] Alert persisted with foreign-key link to incident.")

    # 4. Predictions & Temporal Early Warnings
    print("\n[4/7] Auditing ML Classification & Dual-Horizon Temporal Forecasting...")
    pred = await soc_intelligence_repo.record_prediction(
        prediction_id="PRD-2026-001",
        device_id="WEB-01",
        threat_probability=0.88,
        threat_class="MALICIOUS",
        predicted_category="LATERAL_MOVEMENT",
        category_confidence=0.964,
        model_name="RandomForest+LSTM_Ensemble",
        model_version="v2.4.0",
        risk_score=85.0,
        risk_level="CRITICAL",
        alert_id=alt.alertId,
        incident_id=inc.incidentId
    )
    assert pred.predictionId == "PRD-2026-001"

    temporal = await soc_intelligence_repo.record_temporal_prediction(
        prediction_id="TPRD-2026-001",
        device_id="WEB-01",
        current_threat_probability=0.88,
        future_threat_probability=0.96,
        lead_time=18.4,
        impact_stage="CREDENTIAL_EXTRACTION",
        warning_status="HIGH_CONFIDENCE_WARNING",
        prediction_horizon="30s"
    )
    assert temporal.futureThreatProbability > temporal.currentThreatProbability
    assert temporal.warningStatus == "HIGH_CONFIDENCE_WARNING"
    print(f"    Prediction ID      : {pred.predictionId} (Prob={pred.threatProbability})")
    print(f"    Temporal Lead Time : {temporal.leadTime}s (P_future={temporal.futureThreatProbability})")
    print("    [PASS] Predictions and temporal forecasts verified.")

    # 5. TreeSHAP Explainable AI (XAI) Persistence
    print("\n[5/7] Auditing TreeSHAP Forensic Attribution Persistence...")
    xai = await soc_intelligence_repo.record_xai_explanation(
        prediction_id=pred.predictionId,
        model_name="RandomForest+LSTM_Ensemble",
        model_version="v2.4.0",
        base_value=0.120,
        prediction_probability=0.964,
        feature_values={"flow_pkts_per_sec": 1450, "dst_port_diversity_entropy": 4.82},
        feature_importance={"flow_pkts_per_sec": 0.45, "dst_port_diversity_entropy": 0.32},
        shap_contributions={"flow_pkts_per_sec": 0.384, "dst_port_diversity_entropy": 0.292, "syn_flag_ratio": 0.168},
        human_explanation="Anomalous packet rate and destination port diversity triggered lateral movement classifier."
    )
    assert xai.predictionId == pred.predictionId
    assert xai.baseValue == 0.120
    print(f"    Explanation ID     : {xai.explanationId}")
    print(f"    Attributed Cause   : {xai.humanExplanation}")
    print("    [PASS] XAI Shapley attributions persisted.")

    # 6. Quantitative Risk & Attack Path Discovery
    print("\n[6/7] Auditing Quantitative Risk Scoring (P*C*V*I) & Attack Paths...")
    # P=0.98, C=1.0, V=0.8, I=1.0 -> Risk = 78.4
    risk = await soc_intelligence_repo.record_risk_assessment(
        device_id="WEB-01",
        threat_probability=0.98,
        asset_criticality=1.0,
        vulnerability_factor=0.8,
        attack_impact=1.0,
        source="CANONICAL_ENGINE",
        incident_id=inc.incidentId
    )
    assert risk.riskScore == 78.4
    assert risk.riskLevel == "HIGH"
    print(f"    Calculated Risk    : {risk.riskScore} ({risk.riskLevel})")

    path = await soc_intelligence_repo.record_attack_path(
        attack_path_id="PATH-2026-001",
        source_device_id="CLIENT-01",
        destination_device_id="DB-01",
        path=["CLIENT-01", "WEB-01", "DB-01"],
        risk_score=85.0,
        vulnerabilities=["CVE-2026-RCE", "CVE-2026-AUTH-BYPASS"],
        status="ACTIVE_SIMULATED",
        reachability="REACHABLE",
        evidence="Observed lateral hop from compromised Web tier to internal DB",
        incident_id=inc.incidentId
    )
    assert path.attackPathId == "PATH-2026-001"
    print(f"    Attack Vector      : {' -> '.join(path.path)}")
    print(f"    Vector Status      : {path.status}")
    print("    [PASS] Quantitative risk and attack path graph persisted.")

    # 7. Complete Closed-Loop Investigation Query
    print("\n[7/7] Auditing Closed-Loop SOC Investigation Story from PostgreSQL...")
    chain = await soc_intelligence_repo.get_investigation_chain("INC-2026-0916-001")
    assert chain is not None
    assert len(chain.alerts) == 1
    assert len(chain.predictions) == 1
    assert chain.predictions[0].xaiExplanation is not None
    assert len(chain.riskAssessments) == 1
    assert len(chain.attackPaths) == 1

    print(f"    Incident Scope     : {chain.title}")
    print(f"    Correlated Alert   : {chain.alerts[0].alertId} ({chain.alerts[0].eventType})")
    print(f"    Attached ML Model  : {chain.predictions[0].modelName} (Category={chain.predictions[0].predictedCategory})")
    print(f"    Forensic Reason    : {chain.predictions[0].xaiExplanation.humanExplanation}")
    print(f"    Attack Path Vector : {' -> '.join(chain.attackPaths[0].path)}")
    print("    [PASS] Full 7-stage investigation story successfully loaded from database.")

    # Cleanup Ephemeral Test Records
    print("\n[*] Cleaning Up Ephemeral Test Records...")
    await prisma.xaiexplanation.delete(where={"predictionId": pred.predictionId})
    await prisma.prediction.delete(where={"predictionId": pred.predictionId})
    await prisma.temporalprediction.delete(where={"predictionId": temporal.predictionId})
    await prisma.alert.delete(where={"alertId": alt.alertId})
    await prisma.attackpath.delete(where={"attackPathId": path.attackPathId})
    await prisma.riskassessment.delete(where={"riskId": risk.riskId})
    await prisma.incident.delete(where={"incidentId": inc.incidentId})
    await prisma.device.delete(where={"id": "DB-01"})
    await prisma.device.delete(where={"id": "WEB-01"})
    await prisma.device.delete(where={"id": "CLIENT-01"})
    print("    [PASS] Test artifacts cleanly removed.")

    await db_manager.disconnect()
    print("\n" + "=" * 80)
    print("       ALL DAY 187 SOC INTELLIGENCE PERSISTENCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day187_suite())