from typing import Optional, List, Dict, Any
from services.digital_twin.security.pipeline.normalization.canonical_event import CanonicalEvent
from services.digital_twin.security.pipeline.features.feature_definitions import SecurityFeatureVector
from services.digital_twin.security.pipeline.detection.detection_models import (
    DetectionResult, DetectionTypeEnum, DetectionSeverityEnum, ExplainableEvidence
)
from services.digital_twin.security.pipeline.detection.baseline_store import baseline_store

class PipelineDetectionEngine:
    """Explainable anomaly and threat detection engine evaluating feature vectors and event contexts."""

    def __init__(self):
        self.detection_history: List[DetectionResult] = []

    def detect(self, vector: SecurityFeatureVector, event: Optional[CanonicalEvent] = None) -> DetectionResult:
        src = vector.sourceDevice
        target = vector.targetDevice

        # 1. Check for Suricata explicit signature alert passthrough
        if event and event.eventType == "IDS_ALERT" and event.signature:
            det = DetectionResult(
                detected=True,
                detectionType=DetectionTypeEnum.IDS_SIGNATURE_MATCH,
                confidence=0.95,
                severity=DetectionSeverityEnum.CRITICAL if event.severity.value == "CRITICAL" else DetectionSeverityEnum.HIGH,
                targetDevice=target,
                sourceDevice=src,
                evidence=[
                    ExplainableEvidence(
                        metric="ids_signature",
                        observedValue=1.0,
                        expectedBaseline=0.0,
                        deviationScore=1.0,
                        reason=f"Direct IDS rule match: {event.signature}"
                    )
                ],
                features={"signature": event.signature, "port": event.port},
                detectionSource="SURICATA",
                summary=f"Potential suspicious behaviour detected: IDS alert match ({event.signature})"
            )
            self.detection_history.append(det)
            return det

        # 2. Port Reconnaissance / Sweep Detection
        z_ports = baseline_store.calculate_z_score(target, "uniqueDestinationPorts", float(vector.uniqueDestinationPorts))
        if vector.uniqueDestinationPorts >= 4 or z_ports >= 3.0:
            b_ports = baseline_store.get_baseline(target, "uniqueDestinationPorts")
            confidence = min(0.98, round(0.65 + (vector.uniqueDestinationPorts * 0.05), 2))
            det = DetectionResult(
                detected=True,
                detectionType=DetectionTypeEnum.PORT_ANOMALY,
                confidence=confidence,
                severity=DetectionSeverityEnum.MEDIUM if vector.uniqueDestinationPorts < 10 else DetectionSeverityEnum.HIGH,
                targetDevice=target,
                sourceDevice=src,
                evidence=[
                    ExplainableEvidence(
                        metric="uniqueDestinationPorts",
                        observedValue=float(vector.uniqueDestinationPorts),
                        expectedBaseline=b_ports.mean,
                        deviationScore=round(z_ports, 2),
                        reason=f"Observed {vector.uniqueDestinationPorts} unique destination ports probed (Z-score: {z_ports:.1f})"
                    )
                ],
                features={"uniqueDestinationPorts": vector.uniqueDestinationPorts, "portAttemptCount": vector.portAttemptCount},
                summary="Potential suspicious behaviour detected: unusual horizontal/vertical port discovery pattern"
            )
            self.detection_history.append(det)
            return det

        # 3. Volumetric Traffic Saturation Spike
        z_bytes = baseline_store.calculate_z_score(target, "byteRate", vector.byteRate)
        z_pkts = baseline_store.calculate_z_score(target, "packetRate", vector.packetRate)
        if z_bytes >= 3.0 or z_pkts >= 3.0:
            b_bytes = baseline_store.get_baseline(target, "byteRate")
            confidence = min(0.95, round(0.70 + (max(z_bytes, z_pkts) * 0.04), 2))
            det = DetectionResult(
                detected=True,
                detectionType=DetectionTypeEnum.TRAFFIC_SPIKE,
                confidence=confidence,
                severity=DetectionSeverityEnum.HIGH if max(z_bytes, z_pkts) >= 5.0 else DetectionSeverityEnum.MEDIUM,
                targetDevice=target,
                sourceDevice=src,
                evidence=[
                    ExplainableEvidence(
                        metric="byteRate",
                        observedValue=vector.byteRate,
                        expectedBaseline=b_bytes.mean,
                        deviationScore=round(z_bytes, 2),
                        reason=f"Byte rate {vector.byteRate} B/s exceeds expected baseline {b_bytes.mean} B/s by {z_bytes:.1f} standard deviations"
                    )
                ],
                features={"byteRate": vector.byteRate, "packetRate": vector.packetRate},
                summary="Potential suspicious behaviour detected: volumetric traffic spike exceeding baseline"
            )
            self.detection_history.append(det)
            return det

        # 4. Low-Jitter C2 Beaconing Pattern
        if vector.connectionCount >= 4 and vector.averageInterval >= 0.5 and vector.intervalVariance <= 0.05:
            confidence = min(0.96, round(0.85 + (1.0 / (vector.intervalVariance + 1.0)) * 0.1, 2))
            det = DetectionResult(
                detected=True,
                detectionType=DetectionTypeEnum.BEACONING_PATTERN,
                confidence=confidence,
                severity=DetectionSeverityEnum.HIGH,
                targetDevice=target,
                sourceDevice=src,
                evidence=[
                    ExplainableEvidence(
                        metric="intervalVariance",
                        observedValue=vector.intervalVariance,
                        expectedBaseline=0.5,
                        deviationScore=round(1.0 - vector.intervalVariance, 3),
                        reason=f"Regular time intervals detected (avg: {vector.averageInterval}s, variance: {vector.intervalVariance}s²)"
                    )
                ],
                features={"averageInterval": vector.averageInterval, "intervalVariance": vector.intervalVariance, "connectionCount": vector.connectionCount},
                summary="Potential suspicious behaviour detected: high-regularity periodic C2 beaconing pattern"
            )
            self.detection_history.append(det)
            return det

        # 5. Outbound Data Exfiltration
        z_out = baseline_store.calculate_z_score(target, "outboundBytes", float(vector.outboundBytes))
        if vector.outboundBytes >= 100000 and vector.bytesDirectionRatio >= 10.0:
            confidence = min(0.99, round(0.80 + (vector.outboundBytes / 500000.0) * 0.15, 2))
            det = DetectionResult(
                detected=True,
                detectionType=DetectionTypeEnum.OUTBOUND_VOLUME_ANOMALY,
                confidence=confidence,
                severity=DetectionSeverityEnum.CRITICAL if vector.outboundBytes >= 250000 else DetectionSeverityEnum.HIGH,
                targetDevice=target,
                sourceDevice=src,
                evidence=[
                    ExplainableEvidence(
                        metric="outboundBytes",
                        observedValue=float(vector.outboundBytes),
                        expectedBaseline=5000.0,
                        deviationScore=round(z_out, 2),
                        reason=f"Massive asymmetric egress: {vector.outboundBytes} bytes (ratio: {vector.bytesDirectionRatio}x)"
                    )
                ],
                features={"outboundBytes": vector.outboundBytes, "bytesDirectionRatio": vector.bytesDirectionRatio},
                summary="Potential suspicious behaviour detected: anomalous outbound data transfer volume"
            )
            self.detection_history.append(det)
            return det

        # 6. Authentication Anomaly
        if vector.failedConnectionCount >= 3 and vector.failedConnectionRatio >= 0.5:
            confidence = min(0.94, round(0.70 + vector.failedConnectionRatio * 0.25, 2))
            det = DetectionResult(
                detected=True,
                detectionType=DetectionTypeEnum.AUTHENTICATION_ANOMALY,
                confidence=confidence,
                severity=DetectionSeverityEnum.HIGH,
                targetDevice=target,
                sourceDevice=src,
                evidence=[
                    ExplainableEvidence(
                        metric="failedConnectionRatio",
                        observedValue=vector.failedConnectionRatio,
                        expectedBaseline=0.05,
                        deviationScore=round(vector.failedConnectionRatio / 0.05, 1),
                        reason=f"High failure frequency: {vector.failedConnectionCount} failures ({vector.failedConnectionRatio*100:.1f}%)"
                    )
                ],
                features={"failedConnectionCount": vector.failedConnectionCount, "failedConnectionRatio": vector.failedConnectionRatio},
                summary="Potential suspicious behaviour detected: abnormal authentication/connection failure rate"
            )
            self.detection_history.append(det)
            return det

        # 7. Benign Traffic
        det_benign = DetectionResult(
            detected=False,
            detectionType=DetectionTypeEnum.BENIGN,
            confidence=0.10,
            severity=DetectionSeverityEnum.INFO,
            targetDevice=target,
            sourceDevice=src,
            features={"packetRate": vector.packetRate, "byteRate": vector.byteRate},
            summary="Traffic observed within normal baseline operational limits"
        )
        self.detection_history.append(det_benign)
        return det_benign

    def clear(self):
        self.detection_history.clear()

pipeline_detection_engine = PipelineDetectionEngine()