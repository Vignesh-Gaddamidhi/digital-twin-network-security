import math
from typing import Dict, Any, List, Optional
import numpy as np

from services.digital_twin.ml.time_series.features.time_series_models import (
    TimeSeriesObservation, RollingFeatureSet, TemporalDynamicMetrics
)

class TemporalFeatureEngine:
    """Computes lag features, rolling statistics, rate of change, and temporal derivatives."""

    DEFAULT_INTERVAL = 5.0  # seconds
    LAG_DEPTH = 3
    ROLLING_WINDOWS = [3, 5]

    PRIMARY_NUMERIC_KEYS = [
        "packetRate", "bytesVal", "bytesPerSecond", "connectionFrequency",
        "flowDuration", "failedConnections", "dnsFrequency", "destinationDiversity"
    ]

    def __init__(self, interval_seconds: float = DEFAULT_INTERVAL):
        self.interval_seconds = interval_seconds
        self.history: List[TimeSeriesObservation] = []

    def process_telemetry_stream(
        self,
        raw_stream: List[Dict[str, Any]],
        device_id: str = "SERVER-01",
        source: str = "CLIENT-01",
        destination: str = "SERVER-01"
    ) -> List[TimeSeriesObservation]:
        observations: List[TimeSeriesObservation] = []

        # Chronological buffer of raw values per feature
        feature_buffers: Dict[str, List[float]] = {k: [] for k in self.PRIMARY_NUMERIC_KEYS}

        for idx, item in enumerate(raw_stream):
            # 1. Extract and cast raw telemetry values
            pkt_rate = float(item.get("packet_rate", item.get("packetRate", 0.0)))
            bytes_val = float(item.get("bytes", item.get("bytesVal", 0.0)))
            byte_rate = float(item.get("bytes_per_second", item.get("bytesPerSecond", 0.0)))
            conn_freq = float(item.get("connection_frequency", item.get("connectionFrequency", 0.0)))
            flow_dur = float(item.get("flow_duration", item.get("flowDuration", 0.0)))
            failed_conn = float(item.get("failed_connections", item.get("failedConnections", 0.0)))
            dns_freq = float(item.get("dns_frequency", item.get("dnsFrequency", 0.0)))
            dest_div = float(item.get("destination_diversity", item.get("destinationDiversity", 0.0)))

            curr_vals = {
                "packetRate": pkt_rate,
                "bytesVal": bytes_val,
                "bytesPerSecond": byte_rate,
                "connectionFrequency": conn_freq,
                "flowDuration": flow_dur,
                "failedConnections": failed_conn,
                "dnsFrequency": dns_freq,
                "destinationDiversity": dest_div
            }

            # 2. Compute Lag Features (t-1, t-2, t-3)
            lags: Dict[str, List[float]] = {}
            for k in self.PRIMARY_NUMERIC_KEYS:
                buf = feature_buffers[k]
                lag_k: List[float] = []
                for lag_idx in range(1, self.LAG_DEPTH + 1):
                    val = buf[-lag_idx] if len(buf) >= lag_idx else curr_vals[k]
                    lag_k.append(round(val, 4))
                lags[k] = lag_k

            # 3. Compute Rolling Statistics
            rolling_dict: Dict[str, RollingFeatureSet] = {}
            for k in self.PRIMARY_NUMERIC_KEYS:
                buf = feature_buffers[k] + [curr_vals[k]]
                for w in self.ROLLING_WINDOWS:
                    slice_vals = buf[-w:]
                    mean_val = float(np.mean(slice_vals))
                    std_val = float(np.std(slice_vals)) if len(slice_vals) > 1 else 0.0
                    rolling_dict[f"{k}_w{w}"] = RollingFeatureSet(
                        windowSize=w,
                        mean=round(mean_val, 4),
                        std=round(std_val, 4),
                        minVal=round(float(np.min(slice_vals)), 4),
                        maxVal=round(float(np.max(slice_vals)), 4),
                        median=round(float(np.median(slice_vals)), 4)
                    )

            # 4. Compute Temporal Derivatives (Rate of Change, Velocity, Acceleration)
            dynamics_dict: Dict[str, TemporalDynamicMetrics] = {}
            for k in self.PRIMARY_NUMERIC_KEYS:
                buf = feature_buffers[k]
                curr_v = curr_vals[k]
                prev_v = buf[-1] if len(buf) >= 1 else curr_v
                prev_prev_v = buf[-2] if len(buf) >= 2 else prev_v

                roc = curr_v - prev_v
                pct_change = (roc / max(1e-5, abs(prev_v))) * 100.0 if prev_v != 0.0 else 0.0
                vel = roc / self.interval_seconds
                prev_vel = (prev_v - prev_prev_v) / self.interval_seconds
                acc = (vel - prev_vel) / self.interval_seconds

                if roc > 1e-4:
                    trend = "INCREASING"
                elif roc < -1e-4:
                    trend = "DECREASING"
                else:
                    trend = "STABLE"

                dynamics_dict[k] = TemporalDynamicMetrics(
                    rateOfChange=round(roc, 4),
                    percentageChange=round(pct_change, 2),
                    velocity=round(vel, 4),
                    acceleration=round(acc, 4),
                    trendDirection=trend
                )

            # Append current values to rolling buffer
            for k in self.PRIMARY_NUMERIC_KEYS:
                feature_buffers[k].append(curr_vals[k])

            # Determine Stage (Baseline vs Pre-Impact vs Impact)
            raw_stage = item.get("stage", "BASELINE")
            if pkt_rate > 150.0 or byte_rate > 200000.0 or failed_conn >= 5.0:
                stage = "IMPACT"
            elif dynamics_dict["packetRate"].velocity > 5.0 or dynamics_dict["bytesPerSecond"].velocity > 10000.0:
                stage = "PRE_IMPACT"
            else:
                stage = raw_stage

            obs = TimeSeriesObservation(
                timeStepIndex=idx,
                intervalSeconds=self.interval_seconds,
                deviceId=device_id,
                source=source,
                destination=destination,
                packetRate=pkt_rate,
                bytesVal=bytes_val,
                bytesPerSecond=byte_rate,
                connectionFrequency=conn_freq,
                flowDuration=flow_dur,
                failedConnections=failed_conn,
                dnsFrequency=dns_freq,
                destinationDiversity=dest_div,
                lagFeatures=lags,
                rollingFeatures=rolling_dict,
                dynamics=dynamics_dict,
                label=item.get("label", item.get("binary_label", "NORMAL")),
                stage=stage,
                metadata=item.get("metadata", {})
            )
            observations.append(obs)

        self.history.extend(observations)
        return observations

    def clear(self):
        self.history.clear()

temporal_feature_engine = TemporalFeatureEngine()