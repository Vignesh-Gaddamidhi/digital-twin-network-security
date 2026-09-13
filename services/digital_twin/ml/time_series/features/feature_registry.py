import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

ROOT_DIR = Path(__file__).resolve().parents[5]
REGISTRY_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series"

class TemporalFeatureDefinition(BaseModel):
    featureName: str
    baseFeature: str
    calculationType: str  # LAG, ROLLING_MEAN, ROLLING_STD, RATE_OF_CHANGE, PERCENT_CHANGE, TREND
    unit: str
    windowSize: Optional[int] = None
    lagDepth: Optional[int] = None
    missingValuePolicy: str = "BACKFILL_INITIAL_VALUE"
    expectedRange: List[float] = Field(default_factory=lambda: [0.0, 1.0])
    featureVersion: str = "ts-feat-v1.0"
    description: str

class TemporalFeatureRegistry:
    """Manages formal registry metadata and schema contracts for all time-series features."""

    def __init__(self, registry_dir: Path = REGISTRY_DIR):
        self.registry_dir = registry_dir
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.registry: Dict[str, TemporalFeatureDefinition] = {}
        self._build_standard_registry()

    def _build_standard_registry(self):
        definitions = [
            # Packet Rate Features
            TemporalFeatureDefinition(
                featureName="packet_rate",
                baseFeature="packet_rate",
                calculationType="RAW_VALUE",
                unit="pkts/s",
                expectedRange=[0.0, 10000.0],
                description="Instantaneous packet rate per observation window."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_lag_1",
                baseFeature="packet_rate",
                calculationType="LAG",
                unit="pkts/s",
                lagDepth=1,
                expectedRange=[0.0, 10000.0],
                description="Packet rate observed at step t-1."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_lag_2",
                baseFeature="packet_rate",
                calculationType="LAG",
                unit="pkts/s",
                lagDepth=2,
                expectedRange=[0.0, 10000.0],
                description="Packet rate observed at step t-2."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_rolling_mean_w3",
                baseFeature="packet_rate",
                calculationType="ROLLING_MEAN",
                unit="pkts/s",
                windowSize=3,
                expectedRange=[0.0, 10000.0],
                description="Rolling average of packet rate over 3 steps."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_rolling_std_w3",
                baseFeature="packet_rate",
                calculationType="ROLLING_STD",
                unit="pkts/s",
                windowSize=3,
                expectedRange=[0.0, 5000.0],
                description="Rolling standard deviation of packet rate over 3 steps."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_rate_of_change",
                baseFeature="packet_rate",
                calculationType="RATE_OF_CHANGE",
                unit="pkts/s/step",
                expectedRange=[-5000.0, 5000.0],
                description="First difference: x(t) - x(t-1)."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_percentage_change",
                baseFeature="packet_rate",
                calculationType="PERCENT_CHANGE",
                unit="percent",
                expectedRange=[-100.0, 10000.0],
                description="Relative percentage increase or decrease relative to t-1."
            ),
            TemporalFeatureDefinition(
                featureName="packet_rate_trend",
                baseFeature="packet_rate",
                calculationType="TREND",
                unit="categorical_code",
                expectedRange=[0.0, 3.0],
                description="Trend direction: 0=STABLE, 1=INCREASING, 2=DECREASING, 3=VOLATILE."
            ),

            # Bytes Features
            TemporalFeatureDefinition(
                featureName="bytes_val",
                baseFeature="bytes",
                calculationType="RAW_VALUE",
                unit="bytes",
                expectedRange=[0.0, 100000000.0],
                description="Raw byte volume in window."
            ),
            TemporalFeatureDefinition(
                featureName="bytes_lag_1",
                baseFeature="bytes",
                calculationType="LAG",
                unit="bytes",
                lagDepth=1,
                expectedRange=[0.0, 100000000.0],
                description="Byte volume observed at step t-1."
            ),
            TemporalFeatureDefinition(
                featureName="bytes_rolling_mean_w3",
                baseFeature="bytes",
                calculationType="ROLLING_MEAN",
                unit="bytes",
                windowSize=3,
                expectedRange=[0.0, 100000000.0],
                description="Rolling average of byte volume over 3 steps."
            ),
            TemporalFeatureDefinition(
                featureName="bytes_rate_of_change",
                baseFeature="bytes",
                calculationType="RATE_OF_CHANGE",
                unit="bytes/step",
                expectedRange=[-50000000.0, 50000000.0],
                description="Byte volume rate of change: bytes(t) - bytes(t-1)."
            ),

            # Failed Connections Features
            TemporalFeatureDefinition(
                featureName="failed_connections_val",
                baseFeature="failed_connections",
                calculationType="RAW_VALUE",
                unit="count",
                expectedRange=[0.0, 1000.0],
                description="Failed connection attempts in window."
            ),
            TemporalFeatureDefinition(
                featureName="failed_connections_rolling_mean_w3",
                baseFeature="failed_connections",
                calculationType="ROLLING_MEAN",
                unit="count",
                windowSize=3,
                expectedRange=[0.0, 1000.0],
                description="Rolling mean failed connections over 3 steps."
            ),
            TemporalFeatureDefinition(
                featureName="failed_connections_rate_of_change",
                baseFeature="failed_connections",
                calculationType="RATE_OF_CHANGE",
                unit="count/step",
                expectedRange=[-500.0, 500.0],
                description="Failed connection surge rate."
            ),

            # DNS Frequency Features
            TemporalFeatureDefinition(
                featureName="dns_frequency_val",
                baseFeature="dns_frequency",
                calculationType="RAW_VALUE",
                unit="queries/s",
                expectedRange=[0.0, 1000.0],
                description="DNS queries per second."
            ),
            TemporalFeatureDefinition(
                featureName="dns_frequency_rolling_mean_w3",
                baseFeature="dns_frequency",
                calculationType="ROLLING_MEAN",
                unit="queries/s",
                windowSize=3,
                expectedRange=[0.0, 1000.0],
                description="Rolling mean DNS query frequency over 3 steps."
            ),

            # Destination Diversity Features
            TemporalFeatureDefinition(
                featureName="destination_diversity_val",
                baseFeature="destination_diversity",
                calculationType="RAW_VALUE",
                unit="unique_ratio",
                expectedRange=[0.0, 1.0],
                description="Ratio of unique destinations to total connections."
            ),
            TemporalFeatureDefinition(
                featureName="destination_diversity_trend",
                baseFeature="destination_diversity",
                calculationType="TREND",
                unit="categorical_code",
                expectedRange=[0.0, 3.0],
                description="Trend in destination diversity (flags sweeps and lateral scans)."
            )
        ]

        for d in definitions:
            self.registry[d.featureName] = d

        # Persist registry to JSON
        reg_file = self.registry_dir / "temporal_feature_registry.json"
        with open(reg_file, "w", encoding="utf-8") as f:
            json.dump({k: v.model_dump() for k, v in self.registry.items()}, f, indent=2)

    def get_feature_names(self) -> List[str]:
        return list(self.registry.keys())

temporal_feature_registry = TemporalFeatureRegistry()