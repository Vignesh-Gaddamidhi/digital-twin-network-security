from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.performance import (
    PerformanceLevelEnum, PerformanceMetricSnapshot, 
    PerformanceTelemetryPayload, PerformanceHistoryRecord
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class PerformanceStateEngine:
    """Manages CPU and Memory resource tracking, threshold grading, and combined performance state."""

    LEVEL_ORDER = {
        PerformanceLevelEnum.NORMAL: 1,
        PerformanceLevelEnum.ELEVATED: 2,
        PerformanceLevelEnum.HIGH: 3,
        PerformanceLevelEnum.CRITICAL: 4
    }

    def __init__(self):
        self._current_metrics: Dict[str, PerformanceMetricSnapshot] = {}
        self._history: List[PerformanceHistoryRecord] = []

    def _ensure_device_registered(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found in Device Registry.")

    @classmethod
    def calculateLevel(cls, usage_pct: float) -> PerformanceLevelEnum:
        """Classifies a percentage into project baseline thresholds:
        0 - <60%: NORMAL
        60 - <80%: ELEVATED
        80 - <95%: HIGH
        95 - 100%: CRITICAL
        """
        if usage_pct < 60.0:
            return PerformanceLevelEnum.NORMAL
        elif usage_pct < 80.0:
            return PerformanceLevelEnum.ELEVATED
        elif usage_pct < 95.0:
            return PerformanceLevelEnum.HIGH
        else:
            return PerformanceLevelEnum.CRITICAL

    @classmethod
    def calculateCombinedState(cls, cpu_level: PerformanceLevelEnum, mem_level: PerformanceLevelEnum) -> PerformanceLevelEnum:
        """Returns max(cpu_level, mem_level) based on severity hierarchy."""
        cpu_rank = cls.LEVEL_ORDER[cpu_level]
        mem_rank = cls.LEVEL_ORDER[mem_level]
        return cpu_level if cpu_rank >= mem_rank else mem_level

    def getPerformanceState(self, device_id: str) -> PerformanceMetricSnapshot:
        self._ensure_device_registered(device_id)
        if device_id not in self._current_metrics:
            # Baseline initialization
            self._current_metrics[device_id] = PerformanceMetricSnapshot(
                cpu=0.0,
                memory=0.0,
                cpuLevel=PerformanceLevelEnum.NORMAL,
                memoryLevel=PerformanceLevelEnum.NORMAL,
                performanceState=PerformanceLevelEnum.NORMAL,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
        return self._current_metrics[device_id]

    def recordTelemetry(
        self,
        device_id: str,
        cpu: Optional[float] = None,
        memory: Optional[float] = None,
        source: str = "TELEMETRY"
    ) -> PerformanceMetricSnapshot:
        """Ingests CPU and/or Memory readings, evaluates threshold states, and commits to history."""
        self._ensure_device_registered(device_id)
        curr = self.getPerformanceState(device_id)

        target_cpu = curr.cpu if cpu is None else cpu
        target_mem = curr.memory if memory is None else memory

        # Validate range strictly
        if target_cpu < 0.0 or target_cpu > 100.0:
            raise ValueError(f"CPU usage must be between 0.0 and 100.0%. Got {target_cpu}")
        if target_mem < 0.0 or target_mem > 100.0:
            raise ValueError(f"Memory usage must be between 0.0 and 100.0%. Got {target_mem}")

        cpu_lvl = self.calculateLevel(target_cpu)
        mem_lvl = self.calculateLevel(target_mem)
        comb_state = self.calculateCombinedState(cpu_lvl, mem_lvl)
        now_ts = datetime.now(timezone.utc).isoformat()

        snapshot = PerformanceMetricSnapshot(
            cpu=round(target_cpu, 2),
            memory=round(target_mem, 2),
            cpuLevel=cpu_lvl,
            memoryLevel=mem_lvl,
            performanceState=comb_state,
            timestamp=now_ts
        )
        self._current_metrics[device_id] = snapshot

        # Record to immutable history ledger
        hist_entry = PerformanceHistoryRecord(
            deviceId=device_id,
            cpu=snapshot.cpu,
            cpuLevel=snapshot.cpuLevel,
            memory=snapshot.memory,
            memoryLevel=snapshot.memoryLevel,
            performanceState=snapshot.performanceState,
            source=source,
            timestamp=now_ts
        )
        self._history.append(hist_entry)

        # Sync with main StateEngine cache if available
        try:
            from services.digital_twin.core.state.state_engine import state_engine
            from packages.shared_types.src.device_state import PerformanceStateModel
            if device_id in state_engine._device_states:
                state_engine._device_states[device_id].performance = PerformanceStateModel(
                    cpu=snapshot.cpu,
                    memory=snapshot.memory,
                    networkUtilisation=state_engine._device_states[device_id].performance.networkUtilisation
                )
        except Exception:
            pass

        return snapshot

    def updateCpu(self, device_id: str, cpu_usage: float, source: str = "TELEMETRY") -> PerformanceMetricSnapshot:
        return self.recordTelemetry(device_id, cpu=cpu_usage, source=source)

    def updateMemory(self, device_id: str, memory_usage: float, source: str = "TELEMETRY") -> PerformanceMetricSnapshot:
        return self.recordTelemetry(device_id, memory=memory_usage, source=source)

    def getHistory(self, device_id: Optional[str] = None) -> List[PerformanceHistoryRecord]:
        if device_id:
            self._ensure_device_registered(device_id)
            return [h for h in self._history if h.deviceId == device_id]
        return list(self._history)

    def clear(self):
        self._current_metrics.clear()
        self._history.clear()

performance_state_engine = PerformanceStateEngine()