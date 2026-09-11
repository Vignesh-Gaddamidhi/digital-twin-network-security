from typing import Dict, Any, Optional
from pydantic import BaseModel

class MetricBaseline(BaseModel):
    mean: float
    stdDev: float
    thresholdMultiplier: float = 3.0

class DeviceBaselineProfile(BaseModel):
    deviceId: str
    metrics: Dict[str, MetricBaseline] = {}

class BaselineStore:
    """Manages normal operational behavioral baselines per device."""

    def __init__(self):
        self._profiles: Dict[str, DeviceBaselineProfile] = {}
        self._default_profile = DeviceBaselineProfile(
            deviceId="DEFAULT",
            metrics={
                "packetRate": MetricBaseline(mean=5.0, stdDev=2.0),
                "byteRate": MetricBaseline(mean=2500.0, stdDev=1000.0),
                "connectionRate": MetricBaseline(mean=2.0, stdDev=1.0),
                "uniqueDestinationPorts": MetricBaseline(mean=1.5, stdDev=0.8),
                "failedConnectionRatio": MetricBaseline(mean=0.05, stdDev=0.05),
                "intervalVariance": MetricBaseline(mean=0.5, stdDev=0.2),
                "outboundBytes": MetricBaseline(mean=5000.0, stdDev=2500.0)
            }
        )

    def set_device_baseline(self, device_id: str, profile: DeviceBaselineProfile):
        self._profiles[device_id] = profile

    def get_baseline(self, device_id: str, metric_name: str) -> MetricBaseline:
        if device_id in self._profiles and metric_name in self._profiles[device_id].metrics:
            return self._profiles[device_id].metrics[metric_name]
        return self._default_profile.metrics.get(
            metric_name, MetricBaseline(mean=1.0, stdDev=1.0)
        )

    def calculate_z_score(self, device_id: str, metric_name: str, value: float) -> float:
        b = self.get_baseline(device_id, metric_name)
        sigma = max(b.stdDev, 0.001)
        return max(0.0, (value - b.mean) / sigma)

    def clear(self):
        self._profiles.clear()

baseline_store = BaselineStore()