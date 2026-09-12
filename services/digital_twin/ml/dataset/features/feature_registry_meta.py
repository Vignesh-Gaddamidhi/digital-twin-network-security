from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class FeatureSpec(BaseModel):
    name: str
    category: str
    dataType: str
    unit: str
    calculation: str
    source: str
    missingValuePolicy: str
    minValue: float = 0.0
    maxValue: Optional[float] = None

class FeatureRegistryMeta:
    """Canonical registry documenting each of the 9 required ML feature dimensions."""

    def __init__(self):
        self._specs: Dict[str, FeatureSpec] = {}
        self._initialize_specs()

    def _initialize_specs(self):
        specs = [
            FeatureSpec(
                name="packet_rate",
                category="Packet Rate",
                dataType="float",
                unit="packets/sec",
                calculation="packets / window_duration",
                source="flow/packet telemetry",
                missingValuePolicy="Imputed from duration floor",
                minValue=0.0
            ),
            FeatureSpec(
                name="bytes",
                category="Bytes",
                dataType="int",
                unit="bytes",
                calculation="sum of payload and header bytes",
                source="flow/packet telemetry",
                missingValuePolicy="Defaulted to 0",
                minValue=0.0
            ),
            FeatureSpec(
                name="bytes_per_second",
                category="Bytes",
                dataType="float",
                unit="bytes/sec",
                calculation="bytes / window_duration",
                source="derived volume",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0
            ),
            FeatureSpec(
                name="connection_frequency",
                category="Connection Frequency",
                dataType="float",
                unit="connections/sec",
                calculation="connection_count / window_duration",
                source="session tracker",
                missingValuePolicy="Defaulted to 1.0",
                minValue=0.0
            ),
            FeatureSpec(
                name="port_22_ratio",
                category="Port Distribution",
                dataType="float",
                unit="ratio",
                calculation="port_22_connections / total_connections",
                source="port distribution accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="port_53_ratio",
                category="Port Distribution",
                dataType="float",
                unit="ratio",
                calculation="port_53_connections / total_connections",
                source="port distribution accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="port_80_ratio",
                category="Port Distribution",
                dataType="float",
                unit="ratio",
                calculation="port_80_connections / total_connections",
                source="port distribution accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="port_443_ratio",
                category="Port Distribution",
                dataType="float",
                unit="ratio",
                calculation="port_443_connections / total_connections",
                source="port distribution accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="port_other_ratio",
                category="Port Distribution",
                dataType="float",
                unit="ratio",
                calculation="other_port_connections / total_connections",
                source="port distribution accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="unique_destination_ports",
                category="Port Distribution",
                dataType="int",
                unit="count",
                calculation="cardinality of destination port set",
                source="port accumulator",
                missingValuePolicy="Defaulted to 1",
                minValue=1.0,
                maxValue=65536.0
            ),
            FeatureSpec(
                name="flow_duration",
                category="Flow Duration",
                dataType="float",
                unit="seconds",
                calculation="end_time - start_time",
                source="flow session record",
                missingValuePolicy="Floor minimum 0.001s",
                minValue=0.001
            ),
            FeatureSpec(
                name="tcp_ratio",
                category="Protocol Distribution",
                dataType="float",
                unit="ratio",
                calculation="tcp_events / total_events",
                source="protocol accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="udp_ratio",
                category="Protocol Distribution",
                dataType="float",
                unit="ratio",
                calculation="udp_events / total_events",
                source="protocol accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="icmp_ratio",
                category="Protocol Distribution",
                dataType="float",
                unit="ratio",
                calculation="icmp_events / total_events",
                source="protocol accumulator",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="failed_connections",
                category="Failed Connections",
                dataType="int",
                unit="count",
                calculation="count of rejected or failed handshake attempts",
                source="connection state ledger",
                missingValuePolicy="Defaulted to 0",
                minValue=0.0
            ),
            FeatureSpec(
                name="failed_connection_rate",
                category="Failed Connections",
                dataType="float",
                unit="ratio",
                calculation="failed_connections / total_connections",
                source="connection state ledger",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0,
                maxValue=1.0
            ),
            FeatureSpec(
                name="dns_queries",
                category="DNS Frequency",
                dataType="int",
                unit="count",
                calculation="cumulative count of DNS queries in window",
                source="dns logs / resolver",
                missingValuePolicy="Defaulted to 0",
                minValue=0.0
            ),
            FeatureSpec(
                name="dns_frequency",
                category="DNS Frequency",
                dataType="float",
                unit="queries/sec",
                calculation="dns_queries / window_duration",
                source="dns logs / resolver",
                missingValuePolicy="Defaulted to 0.0",
                minValue=0.0
            ),
            FeatureSpec(
                name="destination_diversity",
                category="Destination Diversity",
                dataType="int",
                unit="count",
                calculation="cardinality of destination IP/device set",
                source="flow routing graph",
                missingValuePolicy="Defaulted to 1",
                minValue=1.0
            ),
            FeatureSpec(
                name="unique_destination_ratio",
                category="Destination Diversity",
                dataType="float",
                unit="ratio",
                calculation="unique_destinations / total_connections",
                source="flow routing graph",
                missingValuePolicy="Defaulted to 1.0",
                minValue=0.0,
                maxValue=1.0
            )
        ]
        for s in specs:
            self._specs[s.name] = s

    def get_spec(self, name: str) -> Optional[FeatureSpec]:
        return self._specs.get(name)

    def list_specs(self) -> List[FeatureSpec]:
        return list(self._specs.values())

    def validate_vector_dict(self, vector_dict: Dict[str, Any]) -> List[str]:
        errors = []
        for name, spec in self._specs.items():
            if name not in vector_dict:
                errors.append(f"Missing required engineered feature '{name}'")
                continue
            val = vector_dict[name]
            if val is None:
                errors.append(f"Feature '{name}' contains null value")
                continue
            if val < spec.minValue:
                errors.append(f"Feature '{name}' value {val} is less than minimum {spec.minValue}")
            if spec.maxValue is not None and val > spec.maxValue:
                errors.append(f"Feature '{name}' value {val} exceeds maximum {spec.maxValue}")
        return errors

feature_registry_meta = FeatureRegistryMeta()