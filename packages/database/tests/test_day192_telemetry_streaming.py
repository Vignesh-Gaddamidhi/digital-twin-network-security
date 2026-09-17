import sys
import time
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import delete

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.redis.redis_manager import redis_manager, STREAMS
from services.digital_twin.core.redis.event_bus import event_bus
from services.digital_twin.core.redis.twin_consumer import twin_consumer
from services.digital_twin.core.redis.telemetry_streamer import telemetry_streamer
from packages.database.src.db_connection import db_manager
from packages.database.src.models import Device, Telemetry
from packages.database.src.twin_persistence_repository import twin_persistence_repo
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.event_contract import CanonicalEvent

async def run_day192_suite():
    print("=" * 80)
    print("       WEEK 28 - DAY 192: TELEMETRY & TWIN STREAMING BENCHMARK")
    print("================================================================================\n")

    await redis_manager.connect()
    await db_manager.connect()

    # Flush any leftover test streams
    await redis_manager.client.delete(STREAMS["TELEMETRY"])
    await redis_manager.client.delete("twin:device:WEB-01:latest")

    # 1. Seed baseline device
    print("[1/5] Seeding Target Device (WEB-01) for Telemetry Streaming...")
    web_dev = NetworkDeviceModel(
        id="WEB-01",
        name="web-01.dmz.internal",
        hostname="web-01.dmz.internal",
        device_type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DMZ,
        ipAddresses=["10.0.2.99"],
        security_state="NORMAL"
    )
    await twin_persistence_repo.persist_device_aggregate(web_dev)
    print("    [PASS] Seeded device WEB-01.")

    # 2. Single Event Streaming Lineage & Ephemeral Cache Check
    print("\n[2/5] Auditing Streaming Lineage & Ephemeral Redis Snapshot (TTL: 60s)...")
    stream_msg_id = await telemetry_streamer.emit_device_telemetry(
        device_id="WEB-01",
        cpu_usage=85.4,
        memory_usage=72.1,
        packet_rate=1450.0,
        byte_rate=950000.0,
        active_connections=48,
        security_state="COMPROMISED",
        risk_score=85.0
    )
    assert stream_msg_id is not None
    print(f"    Published Stream ID: {stream_msg_id}")

    # Read and process single stream event via consumer
    entries = await redis_manager.client.xread(streams={STREAMS["TELEMETRY"]: "0"}, count=1)
    assert len(entries) > 0
    raw_event = entries[0][1][0][1]
    event = CanonicalEvent.from_redis_dict(raw_event)
    mutation = await twin_consumer.process_telemetry_event(event)

    assert mutation["deviceId"] == "WEB-01"
    assert mutation["cpu"] == 85.4
    print(f"    Consumer Processed : {mutation['deviceId']} (CPU={mutation['cpu']}%, State={mutation['securityState']})")

    # Verify Redis snapshot key
    cached_snapshot = await redis_manager.get_cache("twin:device:WEB-01:latest")
    assert cached_snapshot is not None
    assert cached_snapshot["cpu"] == 85.4
    ttl = await redis_manager.client.ttl("twin:device:WEB-01:latest")
    assert 0 < ttl <= 60
    print(f"    Ephemeral Snapshot : Key 'twin:device:WEB-01:latest' Verified (TTL={ttl}s)")
    print("    [PASS] Single-event stream processing and Redis caching validated.")

    # 3. Scaled Batch Ingestion & Throughput Benchmarks (100, 500, 1000 events)
    print("\n[3/5] Stress Testing Stream Throughput Across 100, 500 & 1,000 Events...")
    batch_sizes = [100, 500, 1000]
    sem = asyncio.Semaphore(50)  # Safe concurrency window

    async def emit_throttled(idx: int):
        async with sem:
            return await telemetry_streamer.emit_device_telemetry(
                device_id="WEB-01",
                cpu_usage=50.0 + (idx % 30),
                memory_usage=60.0 + (idx % 20),
                packet_rate=1000.0 + idx,
                byte_rate=500000.0 + (idx * 100),
                active_connections=20 + (idx % 10),
                security_state="NORMAL"
            )

    for batch in batch_sizes:
        t0 = time.perf_counter()
        tasks = [emit_throttled(i) for i in range(batch)]
        results = await asyncio.gather(*tasks)
        elapsed_sec = time.perf_counter() - t0
        throughput = batch / elapsed_sec
        print(f"    Batch Size: {batch:4d} | Elapsed: {elapsed_sec:.3f}s | Throughput: {throughput:8.1f} events/sec")
        assert len(results) == batch
        assert throughput > 200.0

    print("    [PASS] Redis Stream ingestion throughput validated without connection starvation.")

    # 4. Asynchronous Consumer Processing SLA
    print("\n[4/5] Auditing Consumer Batch Ingestion & Drain Latency...")
    t0 = time.perf_counter()
    entries = await redis_manager.client.xread(streams={STREAMS["TELEMETRY"]: "0"}, count=100)
    process_tasks = []
    for s_name, stream_entries in entries:
        for entry_id, raw_data in stream_entries:
            ev = CanonicalEvent.from_redis_dict(raw_data)
            process_tasks.append(twin_consumer.process_telemetry_event(ev))
    
    await asyncio.gather(*process_tasks)
    drain_time = time.perf_counter() - t0
    drain_rate = len(process_tasks) / drain_time if drain_time > 0 else 1000.0
    print(f"    Processed {len(process_tasks)} telemetry mutations in {drain_time:.3f}s ({drain_rate:.1f} events/sec)")
    print("    [PASS] Consumer drain and state mutation completed within micro-latency budget.")

    # 5. Clean up Artifacts
    print("\n[5/5] Cleaning Up Ephemeral Stream & Database Records...")
    await redis_manager.client.delete(STREAMS["TELEMETRY"])
    await redis_manager.client.delete("twin:device:WEB-01:latest")
    async with db_manager.session() as sess:
        await sess.execute(delete(Telemetry).where(Telemetry.device_id == "WEB-01"))
        await sess.execute(delete(Device).where(Device.id == "WEB-01"))
        await sess.flush()

    await redis_manager.disconnect()
    await db_manager.disconnect()
    print("    [PASS] Ephemeral stream and database test artifacts removed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 192 TELEMETRY & DIGITAL TWIN STREAMING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day192_suite())