import re
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from services.digital_twin.ml.dataset.schemas.raw_record_models import RawRecord
from services.digital_twin.ml.dataset.schemas.dataset_models import DatasetSample, BinaryLabelEnum, MulticlassLabelEnum, TelemetrySourceTypeEnum
from services.digital_twin.ml.dataset.cleaning.cleaning_models import (
    CleaningReport, FieldCorrectionAudit, RecordRejectionAudit
)

ROOT_DIR = Path(__file__).resolve().parents[6]
CLEANED_STORAGE_DIR = ROOT_DIR / "datasets" / "cleaned"

class DataCleaningEngine:
    """Production cleaning and preprocessing pipeline turning raw records into ML-ready observations."""

    def __init__(self, cleaned_dir: Path = CLEANED_STORAGE_DIR):
        self.cleaned_dir = cleaned_dir
        self.cleaned_dir.mkdir(parents=True, exist_ok=True)
        self.output_file = self.cleaned_dir / "cleaned_samples.jsonl"
        self.cleaned_samples: List[DatasetSample] = []

    @staticmethod
    def _is_valid_endpoint(val: str) -> bool:
        if not val or str(val).strip() in ("", "-", "UNKNOWN"):
            return False
        clean = str(val).strip()
        try:
            ipaddress.ip_address(clean)
            return True
        except ValueError:
            return bool(re.match(r"^[A-Za-z0-9_\-\.]+$", clean))

    def clean_record(self, raw_rec: RawRecord, report: CleaningReport) -> Optional[DatasetSample]:
        rec_id = raw_rec.rawRecordId
        payload = raw_rec.rawPayload
        report.totalRecords += 1

        if raw_rec.deduplicationStatus == "DUPLICATE":
            report.duplicatesHandled += 1

        # 1. Mandatory Schema Validation
        src = payload.get("src_ip") or payload.get("id.orig_h") or payload.get("source") or payload.get("sourceDevice") or payload.get("sourceIP")
        dst = payload.get("dest_ip") or payload.get("id.resp_h") or payload.get("destination") or payload.get("destinationDevice") or payload.get("destinationIP")

        if not self._is_valid_endpoint(src):
            report.invalidRecords += 1
            report.rejectedRecordsCount += 1
            report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Invalid or missing source endpoint '{src}'", rawRecord=payload))
            return None

        if not self._is_valid_endpoint(dst):
            report.invalidRecords += 1
            report.rejectedRecordsCount += 1
            report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Invalid or missing destination endpoint '{dst}'", rawRecord=payload))
            return None

        # 2. Protocol Normalization
        raw_proto = payload.get("proto") or payload.get("protocol") or "TCP"
        proto_clean = str(raw_proto).strip().upper()
        if proto_clean in ("6", "TCP"):
            proto = "TCP"
        elif proto_clean in ("17", "UDP"):
            proto = "UDP"
        elif proto_clean in ("1", "ICMP"):
            proto = "ICMP"
        else:
            report.invalidRecords += 1
            report.rejectedRecordsCount += 1
            report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Unsupported protocol '{raw_proto}'", rawRecord=payload))
            return None

        if proto_clean != raw_proto:
            report.correctedValuesCount += 1
            report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="protocol", originalValue=raw_proto, correctedValue=proto, correctionReason="Protocol case/format normalization"))

        # 3. Port Normalization & Validation
        raw_port = payload.get("dest_port") or payload.get("id.resp_p") or payload.get("destinationPort") or payload.get("port")
        port = 0
        if raw_port is not None and str(raw_port).strip() not in ("", "-", "null"):
            try:
                port = int(float(str(raw_port).strip()))
                if not (0 <= port <= 65535):
                    report.invalidRecords += 1
                    report.rejectedRecordsCount += 1
                    report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Port out of range 0-65535: {port}", rawRecord=payload))
                    return None
                if not isinstance(raw_port, int) or raw_port != port:
                    report.correctedValuesCount += 1
                    report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="destinationPort", originalValue=raw_port, correctedValue=port, correctionReason="Numeric port coercion"))
            except ValueError:
                report.invalidRecords += 1
                report.rejectedRecordsCount += 1
                report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Unparseable port '{raw_port}'", rawRecord=payload))
                return None
        else:
            report.missingValuesEncountered += 1
            report.correctedValuesCount += 1
            port = 0  # Default non-ported traffic
            report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="destinationPort", originalValue=raw_port, correctedValue=0, correctionReason="Missing port defaulted to 0"))

        # 4. Numerical Fields Validation & Imputation
        raw_bytes = payload.get("bytes") or payload.get("orig_bytes")
        bytes_val = 0
        if raw_bytes is not None and str(raw_bytes).strip() not in ("", "-"):
            try:
                bytes_val = int(float(str(raw_bytes).strip()))
                if bytes_val < 0:
                    report.invalidRecords += 1
                    report.rejectedRecordsCount += 1
                    report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Negative bytes value: {bytes_val}", rawRecord=payload))
                    return None
                if not isinstance(raw_bytes, int) or raw_bytes != bytes_val:
                    report.correctedValuesCount += 1
                    report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="bytes", originalValue=raw_bytes, correctedValue=bytes_val, correctionReason="Numeric byte coercion"))
            except ValueError:
                bytes_val = 0
        else:
            report.missingValuesEncountered += 1
            report.correctedValuesCount += 1
            bytes_val = 0
            report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="bytes", originalValue=raw_bytes, correctedValue=0, correctionReason="Missing bytes defaulted to 0"))

        raw_pkts = payload.get("packets") or payload.get("pkts_toserver") or payload.get("orig_pkts")
        pkts_val = 1
        if raw_pkts is not None and str(raw_pkts).strip() not in ("", "-"):
            try:
                pkts_val = max(1, int(float(str(raw_pkts).strip())))
                if pkts_val < 0:
                    report.invalidRecords += 1
                    report.rejectedRecordsCount += 1
                    report.rejections.append(RecordRejectionAudit(recordId=rec_id, rejectionReason=f"Negative packet value: {pkts_val}", rawRecord=payload))
                    return None
                if not isinstance(raw_pkts, int) or raw_pkts != pkts_val:
                    report.correctedValuesCount += 1
                    report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="packets", originalValue=raw_pkts, correctedValue=pkts_val, correctionReason="Numeric packet coercion"))
            except ValueError:
                pkts_val = 1
        else:
            report.missingValuesEncountered += 1
            report.correctedValuesCount += 1
            pkts_val = 1
            report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="packets", originalValue=raw_pkts, correctedValue=1, correctionReason="Missing packet count defaulted to 1"))

        raw_dur = payload.get("duration") or payload.get("flowDuration")
        duration = 0.001
        if raw_dur is not None and str(raw_dur).strip() not in ("", "-"):
            try:
                duration = max(0.001, float(str(raw_dur).strip()))
            except ValueError:
                duration = 0.001
        else:
            report.missingValuesEncountered += 1
            report.correctedValuesCount += 1
            duration = 0.001
            report.corrections.append(FieldCorrectionAudit(recordId=rec_id, fieldName="flowDuration", originalValue=raw_dur, correctedValue=0.001, correctionReason="Missing flow duration defaulted to 0.001s"))

        # Calculate rates
        byte_rate = payload.get("byteRate")
        if byte_rate is None:
            byte_rate = round(float(bytes_val) / duration, 2)

        pkt_rate = payload.get("packetRate")
        if pkt_rate is None:
            pkt_rate = round(float(pkts_val) / duration, 2)

        # 5. Service Imputation
        service = payload.get("service") or payload.get("eventType")
        if not service or service in ("NETWORK_CONNECTION", "flow"):
            if port == 80:
                service = "HTTP"
            elif port == 443:
                service = "HTTPS"
            elif port == 22:
                service = "SSH"
            elif port == 53 or proto == "UDP" and port == 53:
                service = "DNS"
            else:
                service = f"PORT_{port}"

        # 6. Direction & Ratio Handling
        direction = str(payload.get("direction", "OUTBOUND")).upper()
        dir_ratio = float(payload.get("bytesDirectionRatio") or 1.0)

        # 7. Ground Truth Labels
        scenario_id = payload.get("scenarioId")
        raw_bin_label = str(payload.get("binaryLabel", "NORMAL")).upper()
        bin_label = BinaryLabelEnum.ANOMALOUS if ("ANOMALOUS" in raw_bin_label or scenario_id) else BinaryLabelEnum.NORMAL

        raw_multi = str(payload.get("multiclassLabel", "NORMAL")).upper()
        multi_label = getattr(MulticlassLabelEnum, raw_multi, MulticlassLabelEnum.NORMAL)
        if scenario_id:
            if "PORTSCAN" in scenario_id:
                multi_label = MulticlassLabelEnum.PORT_SCAN
            elif "BRUTEFORCE" in scenario_id:
                multi_label = MulticlassLabelEnum.BRUTE_FORCE
            elif "DOS" in scenario_id:
                multi_label = MulticlassLabelEnum.DOS
            elif "EXFIL" in scenario_id:
                multi_label = MulticlassLabelEnum.DATA_EXFILTRATION

        sample = DatasetSample(
            timestamp=str(payload.get("timestamp") or payload.get("ts") or raw_rec.originalTimestamp or raw_rec.ingestionTimestamp),
            sourceDevice=str(src).strip(),
            destinationDevice=str(dst).strip(),
            telemetrySource=TelemetrySourceTypeEnum.PIPELINE_CANONICAL,
            protocol=proto,
            destinationPort=port,
            service=str(service),
            direction=direction,
            bytes=bytes_val,
            packets=pkts_val,
            flowDuration=duration,
            packetRate=float(pkt_rate),
            byteRate=float(byte_rate),
            connectionFrequency=float(payload.get("connectionFrequency", 1.0)),
            failedConnections=int(payload.get("failedConnections", 0)),
            uniquePorts=int(payload.get("uniquePorts", 1)),
            destinationDiversity=float(payload.get("destinationDiversity", 1.0)),
            dnsFrequency=1.0 if service == "DNS" else 0.0,
            interArrivalTime=float(payload.get("interArrivalTime", 0.0)),
            intervalVariance=float(payload.get("intervalVariance", 0.0)),
            bytesDirectionRatio=dir_ratio,
            binaryLabel=bin_label,
            multiclassLabel=multi_label,
            scenarioId=scenario_id,
            originalEventId=raw_rec.rawRecordId,
            metadata=payload.get("metadata", {})
        )

        report.validRecords += 1
        self.cleaned_samples.append(sample)

        # Write to cleaned storage
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(sample.model_dump_json() + "\n")

        return sample

    def clean_batch(self, records: List[RawRecord]) -> CleaningReport:
        report = CleaningReport()
        for r in records:
            self.clean_record(r, report)
        return report

    def clear(self):
        self.cleaned_samples.clear()
        if self.output_file.exists():
            try:
                self.output_file.unlink()
            except Exception:
                pass

data_cleaning_engine = DataCleaningEngine()