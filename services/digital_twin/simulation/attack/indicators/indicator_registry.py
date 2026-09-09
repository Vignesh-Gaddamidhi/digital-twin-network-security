from typing import Dict, List, Optional
from packages.shared_types.src.attack_indicators import (
    ExpectedIndicatorModel, IndicatorTypeEnum, IndicatorDirectionEnum, IndicatorSeverityEnum
)

class IndicatorRegistry:
    """Central catalog of standard security indicator definitions."""

    def __init__(self):
        self._indicators: Dict[str, ExpectedIndicatorModel] = {}
        self._load_standard_indicators()

    def _load_standard_indicators(self):
        standard = [
            ExpectedIndicatorModel(
                indicatorId="IND-PORT-SWEEP",
                type=IndicatorTypeEnum.UNUSUAL_PORT_ACTIVITY,
                description="Client contacts more than 5 distinct destination ports",
                metric="unique_destination_ports",
                threshold=5.0,
                direction=IndicatorDirectionEnum.GREATER_THAN,
                severity=IndicatorSeverityEnum.MEDIUM
            ),
            ExpectedIndicatorModel(
                indicatorId="IND-FAILED-CONN",
                type=IndicatorTypeEnum.HIGH_FAILED_CONNECTION_RATE,
                description="Failed/RST connection attempts exceed 10",
                metric="failed_connections_count",
                threshold=10.0,
                direction=IndicatorDirectionEnum.GREATER_THAN,
                severity=IndicatorSeverityEnum.HIGH
            ),
            ExpectedIndicatorModel(
                indicatorId="IND-VOL-SPIKE",
                type=IndicatorTypeEnum.TRAFFIC_VOLUME_SPIKE,
                description="Packet throughput exceeds 50 pkts/sec",
                metric="packet_rate_per_second",
                threshold=50.0,
                direction=IndicatorDirectionEnum.GREATER_THAN,
                severity=IndicatorSeverityEnum.HIGH
            ),
            ExpectedIndicatorModel(
                indicatorId="IND-BEACON-PERIODIC",
                type=IndicatorTypeEnum.PERIODIC_TRAFFIC,
                description="Inter-packet timing variance is near zero (periodic beacon)",
                metric="interval_variance_seconds",
                threshold=0.05,
                direction=IndicatorDirectionEnum.LESS_THAN,
                severity=IndicatorSeverityEnum.MEDIUM
            ),
            ExpectedIndicatorModel(
                indicatorId="IND-OUTBOUND-EXFIL",
                type=IndicatorTypeEnum.UNUSUAL_OUTBOUND_VOLUME,
                description="Outbound transfer volume exceeds 50000 bytes",
                metric="outbound_bytes_total",
                threshold=50000.0,
                direction=IndicatorDirectionEnum.GREATER_THAN,
                severity=IndicatorSeverityEnum.CRITICAL
            )
        ]
        for ind in standard:
            self._indicators[ind.indicatorId] = ind

    def register(self, indicator: ExpectedIndicatorModel) -> ExpectedIndicatorModel:
        self._indicators[indicator.indicatorId] = indicator
        return indicator

    def get(self, indicator_id: str) -> Optional[ExpectedIndicatorModel]:
        return self._indicators.get(indicator_id)

    def listAll(self) -> List[ExpectedIndicatorModel]:
        return list(self._indicators.values())

    def clear(self):
        self._indicators.clear()

indicator_registry = IndicatorRegistry()