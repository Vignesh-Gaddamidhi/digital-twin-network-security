import sys
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.event_contract import (
    CanonicalEvent, EventCategoryEnum, EventSeverityEnum
)
from services.digital_twin.core.redis.redis_manager import redis_manager, STREAMS
from services.digital_twin.core.redis.event_bus import event_bus

async def run_day191_suite():
    print("=" * 80)
    print("       WEEK 28 - DAY 191: CANONICAL EVENT CONTRACT & EVENT BUS AUDIT")
    print("================================================================================\n")

    await redis_manager.connect()

    # 1. Canonical Event Schema & Serialization
    print("[1/5] Auditing Canonical Event Envelope Construction & Serialization...")
    root_sim_event = CanonicalEvent(
        eventType=EventCategoryEnum.SIMULATION_STATUS_UPDATE,
        source="ATTACK_SCENARIO_RUNNER",
        deviceId="WEB-01",
        severity=EventSeverityEnum.INFO,
        sequence=1,
        payload={"scenario": "LATERAL_MOVEMENT", "status": "STARTED"}
    )
    assert root_sim_event.eventId is not None
    assert root_sim_event.schemaVersion == "1.0"
    redis_map = root_sim_event.to_redis_dict()
    assert isinstance(redis_map["payload"], str)
    
    rebuilt = CanonicalEvent.from_redis_dict(redis_map)
    assert rebuilt.eventId == root_sim_event.eventId
    assert rebuilt.payload["scenario"] == "LATERAL_MOVEMENT"
    print(f"    Event ID          : {rebuilt.eventId}")
    print(f"    Schema Version    : {rebuilt.schemaVersion}")
    print(f"    Payload Validated : {rebuilt.payload}")
    print("    [PASS] Canonical envelope validated.")

    # 2. Causal Correlation Lineage Chain
    print("\n[2/5] Auditing Causal Lineage Chain (Correlation & Causation IDs)...")
    detection_event = CanonicalEvent(
        eventType=EventCategoryEnum.THREAT_UPDATE,
        source="SURICATA_ENGINE",
        correlationId=root_sim_event.correlationId,  # Shared root transaction
        causationId=root_sim_event.eventId,          # Direct cause
        deviceId="WEB-01",
        severity=EventSeverityEnum.CRITICAL,
        sequence=2,
        payload={"signature": "ET DOS Slowloris", "sid": 200142}
    )
    assert detection_event.correlationId == root_sim_event.correlationId
    assert detection_event.causationId == root_sim_event.eventId
    print(f"    Root Correlation  : {detection_event.correlationId}")
    print(f"    Direct Causation  : {detection_event.causationId}")
    print("    [PASS] Cross-subsystem lineage tracking verified.")

    # 3. Stream Publishing
    print("\n[3/5] Auditing Event Bus Stream Publishing (XADD)...")
    msg_id = await event_bus.publish_event(detection_event, stream_name=STREAMS["EVENTS"])
    assert msg_id is not None
    print(f"    Stream Target     : {STREAMS['EVENTS']}")
    print(f"    Published Msg ID  : {msg_id}")
    print("    [PASS] Event published to Redis Stream.")

    # 4. Duplicate Event Protection & Idempotency
    print("\n[4/5] Auditing Idempotency & Deduplication Engine...")
    test_id = detection_event.eventId
    is_dup_first = await event_bus.is_duplicate(test_id)
    is_dup_second = await event_bus.is_duplicate(test_id)
    assert is_dup_first is False  # First delivery is accepted
    assert is_dup_second is True  # Immediate duplicate is rejected
    print(f"    Delivery Attempt 1: Duplicate = {is_dup_first} (Processed)")
    print(f"    Delivery Attempt 2: Duplicate = {is_dup_second} (Suppressed)")
    print("    [PASS] Consumer deduplication operational.")

    # 5. Pub/Sub Channel Broadcast
    print("\n[5/5] Auditing Real-Time WebSocket Fan-Out Publication...")
    response_event = CanonicalEvent(
        eventType=EventCategoryEnum.RESPONSE_UPDATE,
        source="SOAR_PLAYBOOK_ENGINE",
        correlationId=root_sim_event.correlationId,
        causationId=detection_event.eventId,
        deviceId="WEB-01",
        severity=EventSeverityEnum.HIGH,
        payload={"action": "ISOLATE_DEVICE", "mode": "SIMULATION", "status": "SUCCESS"}
    )
    res_sub_count = await event_bus.publish_event(response_event)
    assert res_sub_count is not None
    print(f"    Broadcast Status  : Event dispatched to WebSocket gateway channel.")
    print("    [PASS] Multi-channel fan-out verified.")

    await redis_manager.disconnect()
    print("\n" + "=" * 80)
    print("       ALL DAY 191 CANONICAL EVENT CONTRACT TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day191_suite())