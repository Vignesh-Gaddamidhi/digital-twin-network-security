import sys
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.redis.redis_manager import redis_manager, STREAMS
from services.digital_twin.core.redis.intelligence_consumers import ml_consumer, risk_consumer
from services.digital_twin.core.redis.soar_consumers import alert_consumer, attack_path_consumer, incident_consumer
from packages.database.src.db_connection import db_manager
from packages.shared_types.src.event_contract import (
    CanonicalEvent, EventCategoryEnum, EventSeverityEnum
)

async def run_day194_suite():
    print("=" * 80)
    print("       WEEK 28 - DAY 194: INTELLIGENCE & SECURITY CONSUMER PIPELINE")
    print("================================================================================\n")

    await redis_manager.connect()
    await db_manager.connect()

    # 1. ML Inference Consumer & SHAP Drivers
    print("[1/5] Auditing ML Inference Consumer & TreeSHAP Attribution...")
    traffic_event = CanonicalEvent(
        eventType=EventCategoryEnum.TRAFFIC_UPDATE,
        source="NETFLOW_V9_COLLECTOR",
        deviceId="WEB-01",
        payload={
            "flow_pkts_per_sec": 1450.0,
            "dst_port_diversity_entropy": 4.82,
            "syn_flag_count_ratio": 0.92
        }
    )
    pred_res = await ml_consumer.run_inference(traffic_event)
    assert pred_res["currentProbability"] > 0.80
    assert pred_res["classification"] == "MALICIOUS"
    assert len(pred_res["shapDrivers"]) == 3
    print(f"    Current Probability: {pred_res['currentProbability']} ({pred_res['classification']})")
    print(f"    Threat Category    : {pred_res['threatCategory']}")
    print(f"    TreeSHAP Driver 1  : {pred_res['shapDrivers'][0]['feature']} = {pred_res['shapDrivers'][0]['weight']}")
    print("    [PASS] ML dual-horizon inference and explainability attributions verified.")

    # 2. Quantitative Risk Consumer
    print("\n[2/5] Auditing Quantitative Risk Consumer (P * C * V * I)...")
    pred_event = CanonicalEvent(
        eventType=EventCategoryEnum.PREDICTION_UPDATE,
        source="ML_INFERENCE_CONSUMER",
        deviceId="WEB-01",
        correlationId=traffic_event.correlationId,
        causationId=traffic_event.eventId,
        payload=pred_res
    )
    risk_res = await risk_consumer.evaluate_risk(pred_event)
    assert risk_res["compositeScore"] >= 70.0
    assert risk_res["tier"] == "CRITICAL"
    print(f"    Evaluated Asset    : {risk_res['deviceId']}")
    print(f"    Formula Calculation: {risk_res['p']} * {risk_res['c']} * {risk_res['v']} * {risk_res['i']} -> Score: {risk_res['compositeScore']}")
    print(f"    Risk Classification: {risk_res['tier']}")
    print("    [PASS] Quantitative risk calculation verified.")

    # 3. Alert Consumer & Persistent Database Triage
    print("\n[3/5] Auditing Alert Consumer & Database Write...")
    alert_res1 = await alert_consumer.process_alert(pred_event)
    assert alert_res1["alertId"].startswith("ALT-")
    assert alert_res1["status"] == "NEW"
    print(f"    Triage Alert 1     : {alert_res1['alertId']} on {alert_res1['deviceId']} (Severity={alert_res1['severity']})")
    print("    [PASS] Alert generated and database record queued.")

    # 4. Attack Path Consumer Graph Traversal
    print("\n[4/5] Auditing Attack Path Consumer Traversal...")
    risk_event = CanonicalEvent(
        eventType=EventCategoryEnum.RISK_UPDATE,
        source="RISK_CONSUMER",
        deviceId="WEB-01",
        correlationId=traffic_event.correlationId,
        causationId=pred_event.eventId,
        payload=risk_res
    )
    path_res = await attack_path_consumer.trace_attack_path(risk_event)
    assert len(path_res["hops"]) == 3
    assert path_res["hops"][0]["node"] == "CLIENT-01"
    assert path_res["hops"][2]["node"] == "DB-01"
    print(f"    Traversed Path ID  : {path_res['pathId']}")
    print(f"    Vector Sequence    : {path_res['hops'][0]['node']} -> {path_res['hops'][1]['node']} -> {path_res['hops'][2]['node']}")
    print(f"    Target Exploit     : {path_res['activeExploit']} (Port {path_res['vulnerabilityPort']})")
    print("    [PASS] Multi-hop graph traversal verified.")

    # 5. Multi-Alert Incident Correlation
    print("\n[5/5] Auditing Multi-Alert Correlation & Incident Promotion...")
    # Generate second correlated alert
    sig_event = CanonicalEvent(
        eventType=EventCategoryEnum.THREAT_UPDATE,
        source="SURICATA",
        deviceId="WEB-01",
        correlationId=traffic_event.correlationId,
        severity=EventSeverityEnum.CRITICAL,
        payload={"signature": "ET DOS Slowloris", "confidence": 0.99}
    )
    alert_res2 = await alert_consumer.process_alert(sig_event)
    print(f"    Triage Alert 2     : {alert_res2['alertId']} on {alert_res2['deviceId']}")

    incident_res = await incident_consumer.correlate_incident(
        alerts=[alert_res1, alert_res2],
        correlation_id=traffic_event.correlationId
    )
    assert incident_res is not None
    assert incident_res["linkedAlertsCount"] == 2
    assert "Sarah Connor" in incident_res["assignedOperator"]
    print(f"    Created SOAR Case  : {incident_res['incidentId']}")
    print(f"    Case Title         : {incident_res['title']}")
    print(f"    Linked Alerts      : {incident_res['linkedAlertsCount']}")
    print(f"    Assigned Operator  : {incident_res['assignedOperator']}")
    print("    [PASS] Multi-alert correlation into SOAR incident verified.")

    # Cleanup
    await redis_manager.client.delete(STREAMS["EVENTS"])
    await redis_manager.client.delete(STREAMS["ALERTS"])
    await redis_manager.disconnect()
    await db_manager.disconnect()

    print("\n" + "=" * 80)
    print("       ALL DAY 194 INTELLIGENCE & SECURITY CONSUMER TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day194_suite())