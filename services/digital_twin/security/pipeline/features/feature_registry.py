from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from services.digital_twin.security.pipeline.features.feature_definitions import SecurityFeatureVector

class FeatureDescriptor(BaseModel):
    name: str
    dimension: str
    dataType: str
    description: str
    minValue: float = 0.0
    maxValue: Optional[float] = None

class FeatureRegistry:
    """Registry maintaining metadata, constraints, and validation rules for all features."""

    def __init__(self):
        self._descriptors: Dict[str, FeatureDescriptor] = {}
        self._register_default_descriptors()

    def _register_default_descriptors(self):
        defaults = [
            FeatureDescriptor(name="packetCount", dimension="Volume", dataType="int", description="Total packets in window"),
            FeatureDescriptor(name="byteCount", dimension="Volume", dataType="int", description="Total bytes in window"),
            FeatureDescriptor(name="packetRate", dimension="Volume", dataType="float", description="Packets per second"),
            FeatureDescriptor(name="byteRate", dimension="Volume", dataType="float", description="Bytes per second"),
            FeatureDescriptor(name="connectionCount", dimension="Connection", dataType="int", description="Total connections initialized"),
            FeatureDescriptor(name="failedConnectionRatio", dimension="Connection", dataType="float", description="Ratio of failed to total connections", maxValue=1.0),
            FeatureDescriptor(name="uniqueDestinationPorts", dimension="Port", dataType="int", description="Count of distinct destination ports probed"),
            FeatureDescriptor(name="protocolRatioTCP", dimension="Protocol", dataType="float", description="Ratio of TCP frames", maxValue=1.0),
            FeatureDescriptor(name="intervalVariance", dimension="Timing", dataType="float", description="Variance in seconds^2 between consecutive packets"),
            FeatureDescriptor(name="outboundBytes", dimension="Direction", dataType="int", description="Cumulative outbound payload bytes")
        ]
        for d in defaults:
            self._descriptors[d.name] = d

    def get_descriptor(self, name: str) -> Optional[FeatureDescriptor]:
        return self._descriptors.get(name)

    def list_descriptors(self) -> List[FeatureDescriptor]:
        return list(self._descriptors.values())

    @staticmethod
    def validate_vector(vec: SecurityFeatureVector) -> List[str]:
        errors = []
        if vec.packetRate < 0:
            errors.append("packetRate cannot be negative")
        if vec.byteRate < 0:
            errors.append("byteRate cannot be negative")
        if not (0.0 <= vec.failedConnectionRatio <= 1.0):
            errors.append(f"failedConnectionRatio out of bounds: {vec.failedConnectionRatio}")
        if not (0.0 <= vec.protocolRatioTCP <= 1.0):
            errors.append(f"protocolRatioTCP out of bounds: {vec.protocolRatioTCP}")
        if vec.intervalVariance < 0:
            errors.append("intervalVariance cannot be negative")
        return errors

feature_registry = FeatureRegistry()