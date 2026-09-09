from typing import List, Dict, Any
from datetime import datetime
from packages.shared_types.src.protocol_traffic import UnifiedTrafficEventModel

class IndicatorEvaluator:
    """Extracts analytical telemetry metrics from raw simulation event streams."""

    @staticmethod
    def extract_metrics(events: List[UnifiedTrafficEventModel], duration_seconds: float = 1.0) -> Dict[str, float]:
        if not events:
            return {}

        effective_duration = max(1.0, duration_seconds)
        total_packets = len(events)
        total_bytes = sum(e.bytes for e in events)

        # Port spreads
        ports = [e.destinationPort for e in events if e.destinationPort is not None]
        unique_ports = len(set(ports))

        # TCP connection failures (RST or FAILED state)
        failed_conns = sum(
            1 for e in events
            if (e.tcpState and e.tcpState.value == "FAILED") or (e.details and e.details.get("flag") == "RST")
        )

        # Connection creations (SYN or CONNECTING)
        conn_attempts = sum(
            1 for e in events
            if (e.tcpState and e.tcpState.value == "CONNECTING") or (e.details and e.details.get("flag") == "SYN")
        )

        # DNS query frequency
        dns_events = sum(
            1 for e in events
            if e.destinationPort == 53 or (e.details and e.details.get("app") == "DNS")
        )

        # Inter-arrival timing variance and mean interval
        timestamps = []
        for e in events:
            try:
                dt = datetime.fromisoformat(e.timestamp)
                timestamps.append(dt.timestamp())
            except Exception:
                pass

        interval_variance = 999.0
        mean_int = 0.2
        if len(timestamps) > 2:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            mean_int = sum(intervals) / len(intervals)
            interval_variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)

        # Authentication Telemetry Metrics
        auth_failures = sum(
            1 for e in events
            if (e.details and e.details.get("auth_event") in ("AUTH_FAILURE", "FAILED")) or
               (e.details and e.details.get("subsystem") == "AUTH" and e.tcpState and e.tcpState.value == "FAILED")
        )
        auth_attempts = sum(
            1 for e in events
            if (e.details and e.details.get("subsystem") == "AUTH" and e.details.get("auth_event") == "AUTH_ATTEMPT") or
               (e.details and e.details.get("subsystem") == "AUTH" and e.direction and e.direction.value == "OUTBOUND")
        )
        auth_successes = sum(
            1 for e in events
            if e.details and e.details.get("auth_event") == "AUTH_SUCCESS"
        )

        auth_failure_ratio = (float(auth_failures) / float(auth_attempts)) if auth_attempts > 0 else 0.0

        return {
            "unique_destination_ports": float(unique_ports),
                        "packet_rate_per_second": float(total_packets / effective_duration),
            "high_packet_rate": float(total_packets / effective_duration),
            "peak_network_utilisation": float(max([e.details.get("network_utilisation", 20.0) for e in events if e.details] or [20.0])),
            "failed_connections_count": float(failed_conns),
            "connection_rate_per_second": float(conn_attempts / effective_duration),
            "outbound_bytes_total": float(total_bytes),
            "dns_query_frequency": float(dns_events / effective_duration),
            "interval_variance_seconds": float(interval_variance),
            "auth_failures_total": float(auth_failures),
            "auth_failure_rate_per_sec": float(auth_failures / effective_duration),
            "auth_failure_ratio": float(auth_failure_ratio),
            "mean_auth_failure_interval": float(mean_int)
        }

indicator_evaluator = IndicatorEvaluator()