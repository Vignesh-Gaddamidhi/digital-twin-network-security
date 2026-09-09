import random
from typing import List
from packages.shared_types.src.traffic_pattern import PatternTimingConfig, PatternTypeEnum

class TimingEngine:
    """Calculates deterministic inter-packet timing offsets based on waveform type and jitter."""

    @staticmethod
    def generate_timeline(
        timing: PatternTimingConfig,
        pattern_type: PatternTypeEnum,
        rng: random.Random
    ) -> List[float]:
        duration = timing.durationSeconds
        rate = timing.rateEventsPerSecond
        start_t = timing.startTimeSeconds
        jitter = timing.jitterSeconds

        timestamps: List[float] = []

        # 1. PERIODIC
        if pattern_type == PatternTypeEnum.PERIODIC:
            base_interval = timing.intervalSeconds if timing.intervalSeconds else (1.0 / rate)
            current_t = start_t
            while current_t <= start_t + duration:
                j = rng.uniform(-jitter, jitter) if jitter > 0 else 0.0
                timestamps.append(max(0.0, current_t + j))
                current_t += base_interval

        # 2. BURST
        elif pattern_type == PatternTypeEnum.BURST:
            # Concentrated spikes in tight bursts every second
            burst_count = max(1, int(duration))
            per_burst = max(1, int(round(rate)))
            for b in range(burst_count):
                burst_start = start_t + float(b)
                for _ in range(per_burst):
                    micro_offset = rng.uniform(0.0, 0.05) # Within 50ms
                    timestamps.append(burst_start + micro_offset)

        # 3. REPEATED or SEQUENTIAL
        elif pattern_type in (PatternTypeEnum.REPEATED, PatternTypeEnum.SEQUENTIAL, PatternTypeEnum.RANDOMIZED):
            total_events = max(1, int(round(rate * duration)))
            step = duration / float(total_events)
            for i in range(total_events):
                base = start_t + (i * step)
                j = rng.uniform(-jitter, jitter) if jitter > 0 else 0.0
                timestamps.append(max(0.0, base + j))

        # 4. GRADUAL_INCREASE
        elif pattern_type == PatternTypeEnum.GRADUAL_INCREASE:
            total_events = max(1, int(round(rate * duration)))
            # Exponentially compress intervals (time offsets grow slowly then compress)
            for i in range(total_events):
                frac = float(i) / float(total_events)
                t_offset = duration * (frac ** 1.8)
                timestamps.append(start_t + t_offset)

        # 5. GRADUAL_DECREASE
        elif pattern_type == PatternTypeEnum.GRADUAL_DECREASE:
            total_events = max(1, int(round(rate * duration)))
            for i in range(total_events):
                frac = float(i) / float(total_events)
                t_offset = duration * (1.0 - ((1.0 - frac) ** 1.8))
                timestamps.append(start_t + t_offset)

        timestamps.sort()
        return timestamps

timing_engine = TimingEngine()