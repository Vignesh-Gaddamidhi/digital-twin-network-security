import random
from typing import List, Optional, Dict
from datetime import datetime, timezone

from packages.shared_types.src.web_traffic import (
    WebProtocolEnum, HttpMethodEnum, WebTrafficProfile, HttpTransactionEvent
)
from packages.shared_types.src.protocol_traffic import (
    TransportProtocolEnum, TrafficDirectionEnum, SimulatedTcpStateEnum, UnifiedTrafficEventModel
)

class HttpTrafficGenerator:
    """Generates Layer 7 plaintext HTTP transactions (Port 80)."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()

    def generateTransaction(
        self,
        source_dev: str,
        dest_dev: str,
        method: HttpMethodEnum = HttpMethodEnum.GET,
        path: str = "/",
        status_code: int = 200,
        req_bytes: Optional[int] = None,
        resp_bytes: Optional[int] = None,
        simulation_id: str = "sim-001"
    ) -> HttpTransactionEvent:
        r_bytes = req_bytes or self._rng.randint(300, 600)
        s_bytes = resp_bytes or (self._rng.randint(800, 4096) if status_code == 200 else self._rng.randint(200, 500))

        return HttpTransactionEvent(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=WebProtocolEnum.HTTP,
            destinationPort=80,
            application="WEB",
            direction="OUTBOUND",
            method=method,
            path=path,
            statusCode=status_code,
            requestBytes=r_bytes,
            responseBytes=s_bytes,
            isEncrypted=False
        )


class HttpsTrafficGenerator:
    """Generates Layer 7 encrypted HTTPS transactions (Port 443)."""

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()

    def generateTransaction(
        self,
        source_dev: str,
        dest_dev: str,
        method: HttpMethodEnum = HttpMethodEnum.GET,
        path: str = "/",
        status_code: int = 200,
        req_bytes: Optional[int] = None,
        resp_bytes: Optional[int] = None,
        simulation_id: str = "sim-001"
    ) -> HttpTransactionEvent:
        # TLS encapsulation adds 29-byte framing overhead
        r_bytes = (req_bytes or self._rng.randint(400, 800)) + 29
        s_bytes = (resp_bytes or (self._rng.randint(1500, 6000) if status_code == 200 else self._rng.randint(300, 600))) + 29

        return HttpTransactionEvent(
            simulationId=simulation_id,
            sourceDevice=source_dev,
            destinationDevice=dest_dev,
            protocol=WebProtocolEnum.HTTPS,
            destinationPort=443,
            application="WEB",
            direction="OUTBOUND",
            method=method,
            path=path,
            statusCode=status_code,
            requestBytes=r_bytes,
            responseBytes=s_bytes,
            isEncrypted=True,
            tlsVersion="TLSv1.3"
        )


class WebTrafficOrchestrator:
    """Generates continuous web traffic flows based on a WebTrafficProfile."""

    def __init__(self, seed: int = 12345):
        self._rng = random.Random(seed)
        self.http_gen = HttpTrafficGenerator(self._rng)
        self.https_gen = HttpsTrafficGenerator(self._rng)
        self._history: List[HttpTransactionEvent] = []

    def _sample_status_code(self, dist: Dict[int, float]) -> int:
        codes = list(dist.keys())
        weights = list(dist.values())
        return self._rng.choices(codes, weights=weights, k=1)[0]

    def generateFromProfile(
        self,
        profile: WebTrafficProfile,
        source_dev: str = "client-01",
        simulation_id: str = "sim-001"
    ) -> List[HttpTransactionEvent]:
        generator = self.https_gen if profile.protocol == WebProtocolEnum.HTTPS else self.http_gen
        events = []

        for path in profile.paths:
            status = self._sample_status_code(profile.statusDistribution)
            method = HttpMethodEnum.POST if path in ("/login", "/api/v1/submit") else HttpMethodEnum.GET

            req_b = int(self._rng.gauss(profile.requestSizeMean, 50))
            req_b = max(128, req_b)
            resp_b = int(self._rng.gauss(profile.responseSizeMean, 300)) if status == 200 else 350
            resp_b = max(64, resp_b)

            evt = generator.generateTransaction(
                source_dev=source_dev,
                dest_dev=profile.destination,
                method=method,
                path=path,
                status_code=status,
                req_bytes=req_b,
                resp_bytes=resp_b,
                simulation_id=simulation_id
            )
            events.append(evt)
            self._history.append(evt)

        return events

    def getEvents(self) -> List[HttpTransactionEvent]:
        return list(self._history)

    def clear(self):
        self._history.clear()

web_orchestrator = WebTrafficOrchestrator()