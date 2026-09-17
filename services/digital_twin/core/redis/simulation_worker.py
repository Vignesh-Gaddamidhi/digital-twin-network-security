import json
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from packages.shared_types.src.event_contract import (
    BackgroundJob, JobStatusEnum, CanonicalEvent,
    EventCategoryEnum, EventSeverityEnum, SimulationScenarioEnum
)
from services.digital_twin.core.redis.redis_manager import redis_manager, STREAMS
from services.digital_twin.core.redis.event_bus import event_bus

QUEUE_KEY = "cybertwin:queue:simulation_jobs"
JOB_STATUS_PREFIX = "cybertwin:job:"

class SimulationBackgroundWorker:
    """Manages asynchronous simulation jobs and streams results to Redis."""

    def __init__(self):
        self.max_retries = 3
        self.retry_delay_seconds = 1.0

    async def enqueue_simulation_job(
        self,
        scenario: str,
        target_device_id: str,
        duration_seconds: int = 30,
        speed_multiplier: float = 1.0
    ) -> BackgroundJob:
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()

        job = BackgroundJob(
            params={
                "scenario": scenario,
                "target_device_id": target_device_id,
                "duration_seconds": duration_seconds,
                "speed_multiplier": speed_multiplier
            }
        )

        # Store job status in Redis Key with 1-hour TTL
        job_key = f"{JOB_STATUS_PREFIX}{job.jobId}"
        await redis_manager.set_cache(job_key, job.model_dump(mode="json"), ttl_seconds=3600)

        # Push to job queue list
        await redis_manager.client.rpush(QUEUE_KEY, job.model_dump_json())
        return job

    async def get_job_status(self, job_id: str) -> Optional[BackgroundJob]:
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()

        raw = await redis_manager.get_cache(f"{JOB_STATUS_PREFIX}{job_id}")
        if not raw:
            return None
        if isinstance(raw, dict):
            return BackgroundJob.model_validate(raw)
        return BackgroundJob.model_validate_json(raw)

    async def execute_job_task(self, job: BackgroundJob) -> Dict[str, Any]:
        """
        Executes the simulation scenario, emitting events directly to Redis Streams.
        """
        scenario = job.params.get("scenario", "LATERAL_MOVEMENT_LIKE")
        target_device = job.params.get("target_device_id", "WEB-01")
        correlation_id = str(job.jobId)

        # 1. Publish SIMULATION_STARTED
        start_event = CanonicalEvent(
            eventType=EventCategoryEnum.SIMULATION_STARTED,
            source="SIMULATION_WORKER",
            deviceId=target_device,
            correlationId=correlation_id,
            payload={"scenario": scenario, "jobId": job.jobId, "status": "RUNNING"}
        )
        await event_bus.publish_event(start_event, stream_name=STREAMS["SIMULATION"])

        # 2. Simulate multi-stage scenario pulse
        stages = ["RECONNAISSANCE_SCAN", "EXPLOIT_PAYLOAD", "LATERAL_PIVOT"]
        events_emitted = []

        for idx, stage in enumerate(stages):
            await asyncio.sleep(0.05)  # Accelerated simulation tick
            stage_event = CanonicalEvent(
                eventType=EventCategoryEnum.THREAT_UPDATE,
                source="SIMULATION_WORKER",
                deviceId=target_device,
                correlationId=correlation_id,
                causationId=start_event.eventId,
                severity=EventSeverityEnum.CRITICAL if idx == 1 else EventSeverityEnum.HIGH,
                sequence=idx + 2,
                payload={
                    "stage": stage,
                    "scenario": scenario,
                    "step": idx + 1,
                    "details": f"Simulated {stage} on {target_device}"
                }
            )
            msg_id = await event_bus.publish_event(stage_event, stream_name=STREAMS["SIMULATION"])
            events_emitted.append(msg_id)

        # 3. Publish SIMULATION_COMPLETED
        complete_event = CanonicalEvent(
            eventType=EventCategoryEnum.SIMULATION_COMPLETED,
            source="SIMULATION_WORKER",
            deviceId=target_device,
            correlationId=correlation_id,
            sequence=len(stages) + 2,
            payload={"scenario": scenario, "jobId": job.jobId, "events_count": len(events_emitted)}
        )
        await event_bus.publish_event(complete_event, stream_name=STREAMS["SIMULATION"])

        return {
            "scenario": scenario,
            "target": target_device,
            "stages_completed": len(stages),
            "stream_message_ids": events_emitted
        }

    async def process_next_job(self) -> Optional[BackgroundJob]:
        """Pops and executes the next job with automatic retries up to maxAttempts."""
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()

        raw_item = await redis_manager.client.lpop(QUEUE_KEY)
        if not raw_item:
            return None

        job = BackgroundJob.model_validate_json(raw_item)
        job.status = JobStatusEnum.RUNNING
        job.startedAt = datetime.now(timezone.utc)
        job_key = f"{JOB_STATUS_PREFIX}{job.jobId}"
        await redis_manager.set_cache(job_key, job.model_dump(mode="json"), ttl_seconds=3600)

        while job.attempt <= self.max_retries:
            try:
                res = await self.execute_job_task(job)
                job.status = JobStatusEnum.COMPLETED
                job.completedAt = datetime.now(timezone.utc)
                job.result = res
                await redis_manager.set_cache(job_key, job.model_dump(mode="json"), ttl_seconds=3600)
                return job
            except Exception as e:
                job.attempt += 1
                job.error = str(e)
                if job.attempt <= self.max_retries:
                    job.status = JobStatusEnum.RETRYING
                    await redis_manager.set_cache(job_key, job.model_dump(mode="json"), ttl_seconds=3600)
                    await asyncio.sleep(self.retry_delay_seconds)
                else:
                    job.status = JobStatusEnum.FAILED
                    job.completedAt = datetime.now(timezone.utc)
                    await redis_manager.set_cache(job_key, job.model_dump(mode="json"), ttl_seconds=3600)
                    return job

        return job

simulation_worker = SimulationBackgroundWorker()