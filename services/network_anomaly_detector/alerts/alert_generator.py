from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid

class AlertGenerator:
    """Formats anomaly evaluations into standardized Security Alerts."""

    @staticmethod
    def generate_alert(
        evaluation: Dict[str, Any],
        source_ip: str,
        destination_ip: str,
        protocol: str = "TCP",
        port: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        if not evaluation.get("is_anomaly", False):
            return None

        # Identify primary deviant feature
        deviations = evaluation.get("deviations", {})
        top_dev = max(deviations.items(), key=lambda x: x[1]["penalty"]) if deviations else ("unknown", {})

        return {
            "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": evaluation["severity"],
            "type": "Network Anomaly",
            "source": source_ip,
            "destination": destination_ip,
            "protocol": protocol,
            "port": port,
            "confidence": f"{int(evaluation['confidence'] * 100)}%",
            "anomaly_score": evaluation["anomaly_score"],
            "description": f"Potential anomalous behaviour detected: Primary deviation on '{top_dev[0]}' (Z-score: {top_dev[1].get('z_score')})",
            "feature_evidence": deviations
        }