import sys
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.redis.redis_manager import redis_manager, STREAMS
from services.digital_twin.core.redis.simulation_worker import (
    simulation_worker, QUEUE_KEY, JOB_STATUS_PREFIX
)
from services.digital_twin.core.redis.simulation_consumer import simulation_consumer
from packages.shared_types.src.event_contract import JobStatusEnum, CanonicalEvent

async def run_day193_suite():
    print("=" * 80)
    print("       WEEK 28 - DAY 193: SIMULATION EVENT STREAMING & WORKER AUDIT")
    print("================================================================================\n")

    await redis_manager.connect()

    # Clean up queues
    await redis_manager.client.delete(QUEUE_KEY)
    await redis_manager.client.delete(STREAMS["SIMULATION"])

    # 1. Enqueue Asynchronous Simulation Job
    print("[1/5] Auditing Asynchronous Job Enqueueing...")
    job = await simulation_worker.enqueue_simulation_job(
        scenario="LATERAL_MOVEMENT_LIKE",
        target_device_id="WEB-01",
        duration_seconds=10,
        speed_multiplier=2.0
    )
    assert job.jobId is not None
    assert job.status == JobStatusEnum.QUEUED
    print(f"    Enqueued Job ID   : {job.jobId}")
    print(f"    Initial Status    : {job.status}")

    # Verify status in Redis key
    queried_job = await simulation_worker.get_job_status(job.jobId)
    assert queried_job is not None
    assert queried_job.jobId == job.jobId
    print("    [PASS] Job successfully persisted to Redis queue and status cache.")

    # 2. Worker Processing Execution
    print("\n[2/5] Auditing Background Worker Job Execution...")
    processed_job = await simulation_worker.process_next_job()
    assert processed_job is not None
    assert processed_job.jobId == job.jobId
    assert processed_job.status == JobStatusEnum.COMPLETED
    assert processed_job.completedAt is not None
    print(f"    Worker Executed   : {processed_job.jobId}")
    print(f"    Final Status      : {processed_job.status}")
    print(f"    Stages Completed  : {processed_job.result['stages_completed']}")
    print("    [PASS] Background simulation completed successfully.")

    # 3. Stream Ingestion Verification
    print("\n[3/5] Auditing Simulation Stream Event Delivery (XREAD)...")
    stream_entries = await redis_manager.client.xread(
        streams={STREAMS["SIMULATION"]: "0"}, count=10
    )
    assert len(stream_entries) > 0
    events = stream_entries[0][1]
    assert len(events) >= 4  # START + 3 Stages + COMPLETE
    print(f"    Stream Key        : {STREAMS['SIMULATION']}")
    print(f"    Stream Records    : {len(events)} events captured in stream buffer.")
    print("    [PASS] Simulation lifecycle events verified in Redis Stream.")

    # 4. Consumer Dispatch to Digital Twin
    print("\n[4/5] Auditing Consumer Digital Twin Dispatch...")
    sample_raw = events[1][1]
    event_model = CanonicalEvent.from_redis_dict(sample_raw)
    dispatch_res = await simulation_consumer.handle_simulation_event(event_model)
    assert dispatch_res["processed"] is True
    assert dispatch_res["deviceId"] == "WEB-01"
    print(f"    Consumer Dispatched: Event {event_model.eventType} -> Device {dispatch_res['deviceId']} (State={dispatch_res['state']})")
    print("    [PASS] Digital Twin dispatch confirmed.")

    # 5. Finite Retry Strategy Validation
    print("\n[5/5] Auditing Finite Retry Strategy on Malformed Job...")
    bad_job = await simulation_worker.enqueue_simulation_job(
        scenario="INVALID_SCENARIO_CRASH",
        target_device_id="WEB-01"
    )
    # Patch worker's execute method temporarily to force a fault
    original_execute = simulation_worker.execute_job_task
    async def faulty_execute(j):
        raise RuntimeError("Simulated synthetic engine crash")
    simulation_worker.execute_job_task = faulty_execute

    failed_job = await simulation_worker.process_next_job()
    assert failed_job.status == JobStatusEnum.FAILED
    assert failed_job.attempt == 4  # Initial attempt + 3 retries
    print(f"    Faulty Job ID     : {failed_job.jobId}")
    print(f"    Final Failed State: {failed_job.status} after {failed_job.attempt - 1} retries.")
    print(f"    Caught Error      : {failed_job.error}")
    print("    [PASS] Worker terminated after maxAttempts without hanging.")

    # Restore worker execute
    simulation_worker.execute_job_task = original_execute

    # Clean up
    await redis_manager.client.delete(QUEUE_KEY)
    await redis_manager.client.delete(STREAMS["SIMULATION"])
    await redis_manager.disconnect()

    print("\n" + "=" * 80)
    print("       ALL DAY 193 SIMULATION STREAMING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day193_suite())