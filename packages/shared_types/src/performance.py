from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class PerformanceLevelEnum(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class PerformanceMetricSnapshot(BaseModel):
    cpu: float = Field(..., description="CPU utilization percentage (0.0 - 100.0%)")
    memory: float = Field(..., description="Memory utilization percentage (0.0 - 100.0%)")
    cpuLevel: PerformanceLevelEnum = Field(default=PerformanceLevelEnum.NORMAL)
    memoryLevel: PerformanceLevelEnum = Field(default=PerformanceLevelEnum.NORMAL)
    performanceState: PerformanceLevelEnum = Field(default=PerformanceLevelEnum.NORMAL)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("cpu")
    @classmethod
    def validate_cpu(cls, v: float) -> float:
        if v < 0.0 or v > 100.0:
            raise ValueError(f"CPU utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2)

    @field_validator("memory")
    @classmethod
    def validate_memory(cls, v: float) -> float:
        if v < 0.0 or v > 100.0:
            raise ValueError(f"Memory utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2)

class PerformanceTelemetryPayload(BaseModel):
    cpu: Optional[float] = Field(default=None, description="Optional CPU reading update")
    memory: Optional[float] = Field(default=None, description="Optional Memory reading update")
    source: str = Field(default="TELEMETRY", description="TELEMETRY, SIMULATION, or AGENT")

    @field_validator("cpu")
    @classmethod
    def validate_cpu_opt(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and (v < 0.0 or v > 100.0):
            raise ValueError(f"CPU utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2) if v is not None else None

    @field_validator("memory")
    @classmethod
    def validate_mem_opt(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and (v < 0.0 or v > 100.0):
            raise ValueError(f"Memory utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2) if v is not None else None

class PerformanceHistoryRecord(BaseModel):
    recordId: str = Field(default_factory=lambda: f"perf-{uuid.uuid4().hex[:8]}")
    deviceId: str = Field(..., min_length=1)
    cpu: float
    cpuLevel: PerformanceLevelEnum
    memory: float
    memoryLevel: PerformanceLevelEnum
    performanceState: PerformanceLevelEnum
    source: str = "TELEMETRY"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())