from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class EngineeredFeatureVector(BaseModel):
    vectorId: str = Field(default_factory=lambda: f"FEAT-{uuid.uuid4().hex[:8].upper()}")
    sampleId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # 1. Packet Rate
    packet_rate: float = 0.0

    # 2. Bytes
    bytes: int = 0
    bytes_per_second: float = 0.0

    # 3. Connection Frequency
    connection_frequency: float = 1.0

    # 4. Port Distribution
    port_22_ratio: float = 0.0
    port_53_ratio: float = 0.0
    port_80_ratio: float = 0.0
    port_443_ratio: float = 0.0
    port_other_ratio: float = 0.0
    unique_destination_ports: int = 1

    # 5. Flow Duration
    flow_duration: float = 0.001

    # 6. Protocol Distribution
    tcp_ratio: float = 1.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0

    # 7. Failed Connections
    failed_connections: int = 0
    failed_connection_rate: float = 0.0

    # 8. DNS Frequency
    dns_queries: int = 0
    dns_frequency: float = 0.0

    # 9. Destination Diversity
    destination_diversity: int = 1
    unique_destination_ratio: float = 1.0

    # Targets (Carried alongside for training set linkage, not features)
    binaryLabel: str = "NORMAL"
    multiclassLabel: str = "NORMAL"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_numerical_vector(self) -> List[float]:
        """Returns the flat numerical vector ordered strictly for ML matrix ingestion."""
        return [
            self.packet_rate,
            float(self.bytes),
            self.bytes_per_second,
            self.connection_frequency,
            self.port_22_ratio,
            self.port_53_ratio,
            self.port_80_ratio,
            self.port_443_ratio,
            self.port_other_ratio,
            float(self.unique_destination_ports),
            self.flow_duration,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            float(self.failed_connections),
            self.failed_connection_rate,
            float(self.dns_queries),
            self.dns_frequency,
            float(self.destination_diversity),
            self.unique_destination_ratio
        ]

    def to_feature_dict(self) -> Dict[str, Any]:
        """Returns clean dictionary of all 9 engineered feature categories."""
        return {
            "packet_rate": self.packet_rate,
            "bytes": self.bytes,
            "bytes_per_second": self.bytes_per_second,
            "connection_frequency": self.connection_frequency,
            "port_22_ratio": self.port_22_ratio,
            "port_53_ratio": self.port_53_ratio,
            "port_80_ratio": self.port_80_ratio,
            "port_443_ratio": self.port_443_ratio,
            "port_other_ratio": self.port_other_ratio,
            "unique_destination_ports": self.unique_destination_ports,
            "flow_duration": self.flow_duration,
            "tcp_ratio": self.tcp_ratio,
            "udp_ratio": self.udp_ratio,
            "icmp_ratio": self.icmp_ratio,
            "failed_connections": self.failed_connections,
            "failed_connection_rate": self.failed_connection_rate,
            "dns_queries": self.dns_queries,
            "dns_frequency": self.dns_frequency,
            "destination_diversity": self.destination_diversity,
            "unique_destination_ratio": self.unique_destination_ratio
        }