from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.ml.dataset.schemas.dataset_models import DatasetSample
from services.digital_twin.ml.dataset.features.engineered_feature_vector import EngineeredFeatureVector
from services.digital_twin.ml.dataset.features.feature_registry_meta import feature_registry_meta

ROOT_DIR = Path(__file__).resolve().parents[6]
FEATURES_STORAGE_DIR = ROOT_DIR / "datasets" / "features"

class FeatureEngineeringEngine:
    """Calculates, validates, and stores the 9 required machine learning feature dimensions."""

    def __init__(self, output_dir: Path = FEATURES_STORAGE_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_file = self.output_dir / "engineered_features.jsonl"
        self.engineered_vectors: List[EngineeredFeatureVector] = []

    def engineer_features(self, sample: DatasetSample, window_context: Optional[List[DatasetSample]] = None) -> EngineeredFeatureVector:
        # Context accumulation (single sample or multi-event observation window)
        records = window_context if window_context else [sample]
        total_records = len(records)

        # 1. Packet Rate
        duration = max(0.001, sample.flowDuration)
        tot_pkts = sum(r.packets for r in records)
        pkt_rate = round(float(tot_pkts) / duration, 4) if sample.packetRate == 0.0 else sample.packetRate

        # 2. Bytes & Byte Rate
        tot_bytes = sum(r.bytes for r in records)
        bytes_sec = round(float(tot_bytes) / duration, 2)

        # 3. Connection Frequency
        conn_freq = round(float(total_records) / duration, 4) if total_records > 1 else sample.connectionFrequency

        # 4. Port Distribution (Ports 22, 53, 80, 443, other, and unique count)
        ports = [r.destinationPort for r in records]
        p22 = sum(1 for p in ports if p == 22)
        p53 = sum(1 for p in ports if p == 53)
        p80 = sum(1 for p in ports if p == 80)
        p443 = sum(1 for p in ports if p == 443)
        p_other = total_records - (p22 + p53 + p80 + p443)
        unique_ports = max(sample.uniquePorts, len(set(ports)))

        # 5. Flow Duration
        flow_dur = duration

        # 6. Protocol Distribution (TCP, UDP, ICMP)
        protos = [str(r.protocol).upper() for r in records]
        n_tcp = sum(1 for p in protos if p == "TCP")
        n_udp = sum(1 for p in protos if p == "UDP")
        n_icmp = sum(1 for p in protos if p == "ICMP")

        # 7. Failed Connections & Rate
        failed_count = sum(r.failedConnections for r in records) if total_records > 1 else sample.failedConnections
        failed_rate = round(float(failed_count) / max(1, total_records), 4)

        # 8. DNS Frequency
        dns_count = sum(1 for r in records if r.service == "DNS" or r.destinationPort == 53 or r.dnsFrequency > 0)
        dns_freq = round(float(dns_count) / duration, 4) if dns_count > 0 else 0.0

        # 9. Destination Diversity & Ratio
        destinations = [r.destinationDevice for r in records]
        unique_dest_count = max(int(sample.destinationDiversity), len(set(destinations)))
        unique_dest_ratio = round(float(unique_dest_count) / max(1, total_records), 4)

        vec = EngineeredFeatureVector(
            sampleId=sample.sampleId,
            packet_rate=float(pkt_rate),
            bytes=int(tot_bytes),
            bytes_per_second=float(bytes_sec),
            connection_frequency=float(conn_freq),
            port_22_ratio=round(float(p22) / max(1, total_records), 4),
            port_53_ratio=round(float(p53) / max(1, total_records), 4),
            port_80_ratio=round(float(p80) / max(1, total_records), 4),
            port_443_ratio=round(float(p443) / max(1, total_records), 4),
            port_other_ratio=round(float(p_other) / max(1, total_records), 4),
            unique_destination_ports=int(unique_ports),
            flow_duration=float(flow_dur),
            tcp_ratio=round(float(n_tcp) / max(1, total_records), 4),
            udp_ratio=round(float(n_udp) / max(1, total_records), 4),
            icmp_ratio=round(float(n_icmp) / max(1, total_records), 4),
            failed_connections=int(failed_count),
            failed_connection_rate=float(failed_rate),
            dns_queries=int(dns_count),
            dns_frequency=float(dns_freq),
            destination_diversity=int(unique_dest_count),
            unique_destination_ratio=float(unique_dest_ratio),
            binaryLabel=sample.binaryLabel.value,
            multiclassLabel=sample.multiclassLabel.value,
            metadata={"scenarioId": sample.scenarioId}
        )

        # Validate against registry boundaries
        errors = feature_registry_meta.validate_vector_dict(vec.to_feature_dict())
        if errors:
            raise ValueError(f"Feature vector validation failed: {errors}")

        self.engineered_vectors.append(vec)

        # Append to persistent JSONL
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(vec.model_dump_json() + "\n")

        return vec

    def engineer_batch(self, samples: List[DatasetSample]) -> List[EngineeredFeatureVector]:
        return [self.engineer_features(s) for s in samples]

    def clear(self):
        self.engineered_vectors.clear()
        if self.output_file.exists():
            try:
                self.output_file.unlink()
            except Exception:
                pass

feature_engineering_engine = FeatureEngineeringEngine()