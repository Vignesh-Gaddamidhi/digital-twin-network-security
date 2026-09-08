import random
from typing import List, Optional, Dict, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.dns_traffic import (
    DnsRecordTypeEnum, DnsResponseCodeEnum, DnsTrafficProfile, DnsTransactionEvent
)

class DnsTrafficGenerator:
    """Generates synthetic DNS queries and deterministic DNS answers."""

    DEFAULT_ZONE_DB: Dict[str, Dict[DnsRecordTypeEnum, List[str]]] = {
        "web.internal.test": {
            DnsRecordTypeEnum.A: ["192.168.20.10"],
            DnsRecordTypeEnum.AAAA: ["2001:db8:20::10"],
            DnsRecordTypeEnum.CNAME: ["web-frontend.internal.test"],
            DnsRecordTypeEnum.TXT: ["v=spf1 -all"]
        },
        "db.internal.test": {
            DnsRecordTypeEnum.A: ["192.168.40.10"],
            DnsRecordTypeEnum.AAAA: ["2001:db8:40::10"],
            DnsRecordTypeEnum.TXT: ["db-node-primary"]
        },
        "dns.internal.test": {
            DnsRecordTypeEnum.A: ["192.168.20.30"],
            DnsRecordTypeEnum.AAAA: ["2001:db8:20::30"]
        },
        "mail.internal.test": {
            DnsRecordTypeEnum.A: ["192.168.20.25"],
            DnsRecordTypeEnum.MX: ["10 mail.internal.test"]
        },
        "example.test": {
            DnsRecordTypeEnum.A: ["93.184.216.34"],
            DnsRecordTypeEnum.AAAA: ["2606:2800:220:1:248:1893:25c8:1946"],
            DnsRecordTypeEnum.TXT: ["v=spf1 -all"]
        },
        "api.internal.test": {
            DnsRecordTypeEnum.CNAME: ["web.internal.test"]
        }
    }

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()
        self._zone_db = dict(self.DEFAULT_ZONE_DB)

    def resolve(self, domain: str, qtype: DnsRecordTypeEnum) -> Tuple[DnsResponseCodeEnum, List[str]]:
        domain_clean = domain.strip().lower()
        if domain_clean not in self._zone_db:
            return DnsResponseCodeEnum.NXDOMAIN, []

        records = self._zone_db[domain_clean]
        if qtype in records:
            return DnsResponseCodeEnum.NOERROR, records[qtype]

        # Check if CNAME exists when A/AAAA is requested
        if DnsRecordTypeEnum.CNAME in records and qtype in (DnsRecordTypeEnum.A, DnsRecordTypeEnum.AAAA):
            return DnsResponseCodeEnum.NOERROR, records[DnsRecordTypeEnum.CNAME]

        return DnsResponseCodeEnum.NOERROR, []

    def generateQueryPair(
        self,
        source_dev: str,
        dns_server: str,
        domain: str = "web.internal.test",
        query_type: DnsRecordTypeEnum = DnsRecordTypeEnum.A,
        simulation_id: str = "sim-001"
    ) -> Tuple[DnsTransactionEvent, DnsTransactionEvent]:
        tx_id = self._rng.randint(1000, 65535)
        src_port = self._rng.randint(49152, 65535)
        now_ts = datetime.now(timezone.utc).isoformat()

        # 1. Client Query (Outbound)
        query = DnsTransactionEvent(
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=source_dev,
            destinationDevice=dns_server,
            protocol="UDP",
            sourcePort=src_port,
            destinationPort=53,
            application="DNS",
            direction="OUTBOUND",
            queryType=query_type,
            domain=domain,
            transactionId=tx_id,
            isResponse=False,
            bytes=self._rng.randint(48, 84)
        )

        # 2. Server Response (Inbound to Client)
        rcode, answers = self.resolve(domain, query_type)
        response = DnsTransactionEvent(
            simulationId=simulation_id,
            timestamp=now_ts,
            sourceDevice=dns_server,
            destinationDevice=source_dev,
            protocol="UDP",
            sourcePort=53,
            destinationPort=src_port,
            application="DNS",
            direction="INBOUND",
            queryType=query_type,
            domain=domain,
            transactionId=tx_id,
            isResponse=True,
            rcode=rcode,
            answers=answers,
            ttl=300,
            bytes=self._rng.randint(96, 256) if answers else 48
        )

        return query, response


class DnsTrafficOrchestrator:
    """Manages continuous DNS query workflows based on a DnsTrafficProfile."""

    def __init__(self, seed: int = 12345):
        self._rng = random.Random(seed)
        self.generator = DnsTrafficGenerator(self._rng)
        self._history: List[DnsTransactionEvent] = []

    def _sample_type(self, profile: DnsTrafficProfile) -> DnsRecordTypeEnum:
        types = list(profile.typeWeights.keys())
        weights = list(profile.typeWeights.values())
        return self._rng.choices(types, weights=weights, k=1)[0]

    def generateFromProfile(
        self,
        profile: DnsTrafficProfile,
        source_dev: str = "client-01",
        simulation_id: str = "sim-001"
    ) -> List[DnsTransactionEvent]:
        events = []
        for domain in profile.domains:
            qtype = self._sample_type(profile)
            q, r = self.generator.generateQueryPair(
                source_dev=source_dev,
                dns_server=profile.destinationDnsServer,
                domain=domain,
                query_type=qtype,
                simulation_id=simulation_id
            )
            events.extend([q, r])
            self._history.extend([q, r])
        return events

    def getEvents(self) -> List[DnsTransactionEvent]:
        return list(self._history)

    def clear(self):
        self._history.clear()

dns_orchestrator = DnsTrafficOrchestrator()