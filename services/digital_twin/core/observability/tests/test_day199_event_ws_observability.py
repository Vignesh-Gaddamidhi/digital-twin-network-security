import sys
import time
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.observability.event_ws_observability import (
    event_ws_observability, DropReasonEnum, ConsumerStatusEnum, WebSocketClientStateEnum
)

async def run_day199_suite():
    print("=" * 80)
    print("       WEEK 29 - DAY 199: REDIS, EVENT PIPELINE & WEBSOCKET OBSERVABILITY")
    print("================================================================================\n")

    # 1. Event Throughput & Ingestion Telemetry
    print("[1/7] Testing Event Throughput & Rate Counter Accounting...")
    for _ in range(50):
        event_ws_observability.record_event_published("TRAFFIC_UPDATE", source="NETFLOW")
    for _ in range(25):
        event_ws_observability.record_event_published("SIMULATION_STARTED", source="ATTACK_RUNNER")

    pub_traffic = event_ws_observability.events_published_total[("TRAFFIC_UPDATE", "NETFLOW")]
    pub_sim = event_ws_observability.events_published_total[("SIMULATION_STARTED", "ATTACK_RUNNER")]
    assert pub_traffic == 50
    assert pub_sim == 25
    print(f"    Published: TRAFFIC_UPDATE={pub_traffic} | SIMULATION_STARTED={pub_sim}")
    print("    [PASS] Event publishing counters verified.")

    # 2. Event Processing Latency & End-to-End Latency Tracking
    print("\n[2/7] Testing Consumer Processing Latency & E2E Transit Duration...")
    # Simulate an event published 20ms ago, consumed now, took 10ms to process
    t_pub = time.time() - 0.030
    t_start = event_ws_observability.record_event_consumed(
        event_type="TRAFFIC_UPDATE",
        consumer="twin_consumer",
        source="NETFLOW",
        publish_timestamp=t_pub
    )
    assert event_ws_observability.consumers["twin_consumer"]["status"] == ConsumerStatusEnum.PROCESSING
    
    await asyncio.sleep(0.010)
    event_ws_observability.record_event_completed(
        event_type="TRAFFIC_UPDATE",
        consumer="twin_consumer",
        source="NETFLOW",
        publish_timestamp=t_pub,
        start_processing_time=t_start,
        failed=False,
        retried=False
    )
    assert event_ws_observability.consumers["twin_consumer"]["status"] == ConsumerStatusEnum.IDLE
    assert event_ws_observability.consumers["twin_consumer"]["processed"] == 1

    proc_hist = event_ws_observability.event_processing_latency_hist[("TRAFFIC_UPDATE", "twin_consumer")]
    e2e_hist = event_ws_observability.event_e2e_latency_hist[("TRAFFIC_UPDATE", "twin_consumer")]
    assert proc_hist["count"] == 1
    assert e2e_hist["count"] == 1
    assert e2e_hist["sum"] >= proc_hist["sum"]
    print(f"    Recorded Twin Consumer Latency: Processing={proc_hist['sum']*1000:.2f}ms | E2E={e2e_hist['sum']*1000:.2f}ms")
    print("    [PASS] End-to-end latency calculations verified.")

    # 3. Categorical Dropped Event Audit (No Silent Drops)
    print("\n[3/7] Auditing Non-Silent Event Drop Taxonomy...")
    drop_cases = [
        ("TELEMETRY", "NETFLOW", DropReasonEnum.QUEUE_OVERFLOW),
        ("PREDICTION", "ML_ENGINE", DropReasonEnum.TIMEOUT),
        ("ALERT", "SOAR", DropReasonEnum.INVALID_EVENT),
        ("ATTACK_PATH", "RISK_ENGINE", DropReasonEnum.RESOURCE_LIMIT)
    ]
    for et, src, rsn in drop_cases:
        event_ws_observability.record_event_dropped(et, src, rsn)

    assert event_ws_observability.events_dropped_total[("TELEMETRY", "NETFLOW", "QUEUE_OVERFLOW")] == 1
    assert event_ws_observability.events_dropped_total[("PREDICTION", "ML_ENGINE", "TIMEOUT")] == 1
    assert event_ws_observability.events_dropped_total[("ALERT", "SOAR", "INVALID_EVENT")] == 1
    assert event_ws_observability.events_dropped_total[("ATTACK_PATH", "RISK_ENGINE", "RESOURCE_LIMIT")] == 1
    print("    Verified Dropped Event Records:")
    for k, v in event_ws_observability.events_dropped_total.items():
        print(f"     - Event={k[0]:12} Source={k[1]:12} Reason={k[2]:16} Count={v}")
    print("    [PASS] All dropped events tracked with categorical reasons.")

    # 4. Consumer Health, Backlog & Degradation Transitions
    print("\n[4/7] Testing Consumer Health, Backlog Sizing & Degradation Logic...")
    all_consumers = [
        "twin_consumer", "ml_consumer", "alert_consumer",
        "risk_consumer", "attack_path_consumer", "incident_consumer"
    ]
    for c in all_consumers:
        assert c in event_ws_observability.consumers

    # Trigger degradation threshold on ML consumer
    event_ws_observability.update_consumer_backlog("ml_consumer", 1500)
    assert event_ws_observability.consumers["ml_consumer"]["status"] == ConsumerStatusEnum.DEGRADED

    # Trigger stalled threshold on Incident consumer
    event_ws_observability.update_consumer_backlog("incident_consumer", 6200)
    assert event_ws_observability.consumers["incident_consumer"]["status"] == ConsumerStatusEnum.STALLED

    # Normal backlog on Alert consumer
    event_ws_observability.update_consumer_backlog("alert_consumer", 45)
    assert event_ws_observability.consumers["alert_consumer"]["status"] == ConsumerStatusEnum.IDLE

    print(f"    ML Consumer (Backlog 1500): Status={event_ws_observability.consumers['ml_consumer']['status'].value}")
    print(f"    Incident Consumer (Backlog 6200): Status={event_ws_observability.consumers['incident_consumer']['status'].value}")
    print(f"    Alert Consumer (Backlog 45): Status={event_ws_observability.consumers['alert_consumer']['status'].value}")
    print("    [PASS] Consumer health and queue backlog thresholding active.")

    # 5. WebSocket Connection Lifecycle & Client States
    print("\n[5/7] Auditing WebSocket Session Tracking & Client State Invariants...")
    event_ws_observability.record_ws_connection_opened(WebSocketClientStateEnum.CONNECTED)
    event_ws_observability.record_ws_connection_opened(WebSocketClientStateEnum.CONNECTED)
    assert event_ws_observability.ws_active_connections == 2
    assert event_ws_observability.ws_client_states[WebSocketClientStateEnum.CONNECTED] == 2

    # Client transitions to LIVE after handshake
    event_ws_observability.transition_ws_client_state(WebSocketClientStateEnum.CONNECTED, WebSocketClientStateEnum.LIVE)
    assert event_ws_observability.ws_client_states[WebSocketClientStateEnum.CONNECTED] == 1
    assert event_ws_observability.ws_client_states[WebSocketClientStateEnum.LIVE] == 1

    # Client undergoes reconnection
    event_ws_observability.transition_ws_client_state(WebSocketClientStateEnum.LIVE, WebSocketClientStateEnum.RECONNECTING)
    assert event_ws_observability.ws_reconnects_total == 1
    assert event_ws_observability.ws_client_states[WebSocketClientStateEnum.RECONNECTING] == 1

    # Client terminates session
    event_ws_observability.record_ws_connection_closed(WebSocketClientStateEnum.RECONNECTING)
    assert event_ws_observability.ws_active_connections == 1
    assert event_ws_observability.ws_connections_closed_total == 1
    print(f"    Active Connections: {event_ws_observability.ws_active_connections}")
    print(f"    Reconnections Logged: {event_ws_observability.ws_reconnects_total}")
    print("    [PASS] WebSocket connection lifecycle verified.")

    # 6. WebSocket End-to-End Distribution Path Latency
    print("\n[6/7] Benchmarking End-to-End WebSocket Broadcast Pipeline...")
    t_redis_pub = time.time() - 0.012  # Redis emitted 12ms ago
    event_ws_observability.record_ws_broadcast(
        topic="telemetry",
        redis_timestamp=t_redis_pub
    )
    event_ws_observability.record_ws_broadcast(
        topic="alerts",
        redis_timestamp=t_redis_pub
    )
    # Record a failed frame broadcast
    event_ws_observability.record_ws_broadcast(topic="telemetry", redis_timestamp=t_redis_pub, failed=True)

    assert event_ws_observability.ws_messages_sent_total == 2
    assert event_ws_observability.ws_messages_failed_total == 1
    assert "telemetry" in event_ws_observability.ws_broadcast_latency_hist
    assert "alerts" in event_ws_observability.ws_broadcast_latency_hist
    print(f"    Broadcasts Dispatched: {event_ws_observability.ws_messages_sent_total} | Failures: {event_ws_observability.ws_messages_failed_total}")
    print("    [PASS] WebSocket publication and broadcast latency captured.")

    # 7. OpenMetrics Exposition Rendering
    print("\n[7/7] Generating Prometheus :9090 Exposition Output...")
    rendered = event_ws_observability.render_event_and_ws_exposition()
    assert "# TYPE events_published_total counter" in rendered
    assert "# TYPE events_consumed_total counter" in rendered
    assert "# TYPE events_dropped_total counter" in rendered
    assert "# TYPE event_processing_latency_seconds histogram" in rendered
    assert "# TYPE event_e2e_latency_seconds histogram" in rendered
    assert "# TYPE ws_active_connections gauge" in rendered
    assert "# TYPE ws_broadcast_latency_seconds histogram" in rendered
    assert 'consumer_status{consumer="ml_consumer",state="DEGRADED"} 0' in rendered
    assert 'consumer_status{consumer="alert_consumer",state="IDLE"} 1' in rendered
    print("    Sample Exposition Lines:\n    " + "\n    ".join(rendered.splitlines()[:6]))
    print("    [PASS] Prometheus exposition format validated.")

    print("\n" + "=" * 80)
    print("       ALL DAY 199 EVENT & WEBSOCKET OBSERVABILITY TESTS COMPLETED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day199_suite())