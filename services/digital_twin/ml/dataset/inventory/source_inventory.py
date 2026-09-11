from typing import Dict, Any, Optional, List
from services.digital_twin.ml.dataset.schemas.dataset_models import (
    DatasetSample, BinaryLabelEnum, MulticlassLabelEnum, TelemetrySourceTypeEnum, DatasetMetadata
)
from services.digital_twin.security.pipeline.normalization.canonical_event import CanonicalEvent
from services.digital_twin.security.pipeline.features.feature_definitions import SecurityFeatureVector
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver

class SourceInventoryAdapter:
    """Extracts ML dataset samples from Phase 7-10 telemetry outputs."""

    SCENARIO_LABEL_MAP = {
        "SCN-PORTSCAN-001": MulticlassLabelEnum.PORT_SCAN,
        "SCN-BRUTEFORCE-001": MulticlassLabelEnum.BRUTE_FORCE,
        "SCN-DOS-001": MulticlassLabelEnum.DOS,
        "SCN-DNS-001": MulticlassLabelEnum.DNS_ANOMALY,
        "SCN-BEACON-001": MulticlassLabelEnum.BEACONING,
        "SCN-LATERAL-001": MulticlassLabelEnum.LATERAL_MOVEMENT,
        "SCN-EXFIL-001": MulticlassLabelEnum.DATA_EXFILTRATION
    }

    @classmethod
    def from_canonical_event(
        cls,
        event: CanonicalEvent,
        feature_vector: Optional[SecurityFeatureVector] = None,
        scenario_id: Optional[str] = None
    ) -> DatasetSample:
        # Determine labels
        multi_label = MulticlassLabelEnum.NORMAL
        bin_label = BinaryLabelEnum.NORMAL

        if scenario_id and scenario_id in cls.SCENARIO_LABEL_MAP:
            multi_label = cls.SCENARIO_LABEL_MAP[scenario_id]
            bin_label = BinaryLabelEnum.ANOMALOUS
        elif event.eventType in ("IDS_ALERT", "PORT_ACTIVITY", "AUTH_FAILURE") or event.severity.value in ("HIGH", "CRITICAL"):
            bin_label = BinaryLabelEnum.ANOMALOUS
            if event.port in (21, 22, 23, 25, 8080) and event.eventType == "PORT_ACTIVITY":
                multi_label = MulticlassLabelEnum.PORT_SCAN
            elif event.eventType == "AUTH_FAILURE":
                multi_label = MulticlassLabelEnum.BRUTE_FORCE
            elif event.eventType == "DNS_QUERY" and "tunnel" in str(event.signature or "").lower():
                multi_label = MulticlassLabelEnum.DNS_ANOMALY
            else:
                multi_label = MulticlassLabelEnum.DOS

        # Extract features from event and feature vector
        bytes_val = event.bytes
        pkts_val = event.packets
        port_val = event.port or 80
        proto_str = event.protocol.value

        pkt_rate = feature_vector.packetRate if feature_vector else float(pkts_val)
        byte_rate = feature_vector.byteRate if feature_vector else float(bytes_val)
        conn_freq = feature_vector.connectionRate if feature_vector else 1.0
        failed_conns = feature_vector.failedConnectionCount if feature_vector else 0
        uniq_ports = feature_vector.uniqueDestinationPorts if feature_vector else 1
        inter_arrival = feature_vector.interArrivalTime if feature_vector else 0.0
        int_variance = feature_vector.intervalVariance if feature_vector else 0.0
        dir_ratio = feature_vector.bytesDirectionRatio if feature_vector else 1.0

        dir_str = "OUTBOUND"
        if event.metadata.get("direction"):
            dir_str = str(event.metadata["direction"]).upper()

        src_type_map = {
            "SURICATA": TelemetrySourceTypeEnum.SURICATA_IDS,
            "ZEEK": TelemetrySourceTypeEnum.ZEEK_NSM,
            "SIMULATION": TelemetrySourceTypeEnum.SIMULATION_TRAFFIC
        }
        source_type = src_type_map.get(event.detectionSource.value, TelemetrySourceTypeEnum.PIPELINE_CANONICAL)
        if scenario_id:
            source_type = TelemetrySourceTypeEnum.ATTACK_SCENARIO

        return DatasetSample(
            timestamp=event.eventTimestamp,
            sourceDevice=event.source,
            destinationDevice=event.destination,
            telemetrySource=source_type,
            protocol=proto_str,
            destinationPort=port_val,
            service=event.eventType,
            direction=dir_str,
            bytes=bytes_val,
            packets=pkts_val,
            flowDuration=feature_vector.windowDurationSeconds if feature_vector else 1.0,
            packetRate=pkt_rate,
            byteRate=byte_rate,
            connectionFrequency=conn_freq,
            failedConnections=failed_conns,
            uniquePorts=uniq_ports,
            destinationDiversity=float(uniq_ports),
            dnsFrequency=1.0 if event.eventType == "DNS_QUERY" else 0.0,
            interArrivalTime=inter_arrival,
            intervalVariance=int_variance,
            bytesDirectionRatio=dir_ratio,
            binaryLabel=bin_label,
            multiclassLabel=multi_label,
            scenarioId=scenario_id,
            originalEventId=event.eventId,
            metadata=event.metadata
        )

class DatasetInventoryManager:
    """Manages collection, statistics, and metadata for generated dataset samples."""

    def __init__(self):
        self.samples: List[DatasetSample] = []

    def add_sample(self, sample: DatasetSample):
        self.samples.append(sample)

    def generate_metadata(self, dataset_id: Optional[str] = None, version: str = "1.0.0") -> DatasetMetadata:
        total = len(self.samples)
        normal = sum(1 for s in self.samples if s.binaryLabel == BinaryLabelEnum.NORMAL)
        anomalous = total - normal

        sources = list(set(s.telemetrySource for s in self.samples))

        multi_counts = {}
        for s in self.samples:
            k = s.multiclassLabel.value
            multi_counts[k] = multi_counts.get(k, 0) + 1

        meta = DatasetMetadata(
            datasetId=dataset_id or f"DS-{len(self.samples)}SMP",
            version=version,
            sourceTypes=sources,
            totalSamples=total,
            normalSamples=normal,
            anomalousSamples=anomalous,
            multiclassCounts=multi_counts
        )
        return meta

    def clear(self):
        self.samples.clear()

dataset_inventory = DatasetInventoryManager()