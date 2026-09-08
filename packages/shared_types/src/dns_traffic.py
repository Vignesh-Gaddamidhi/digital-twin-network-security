from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class DnsRecordTypeEnum(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"

class DnsResponseCodeEnum(str, Enum):
    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"

class DnsTrafficProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"dnsprof-{uuid.uuid4().hex[:6]}")
    name: str = "Corporate-DNS-Profile"
    queriesPerMinute: float = Field(default=60.0, ge=0.1, le=6000.0)
    queryTypes: List[DnsRecordTypeEnum] = Field(
        default_factory=lambda: [DnsRecordTypeEnum.A, DnsRecordTypeEnum.AAAA, DnsRecordTypeEnum.CNAME]
    )
    typeWeights: Dict[DnsRecordTypeEnum, float] = Field(
        default_factory=lambda: {
            DnsRecordTypeEnum.A: 0.70,
            DnsRecordTypeEnum.AAAA: 0.15,
            DnsRecordTypeEnum.CNAME: 0.10,
            DnsRecordTypeEnum.TXT: 0.03,
            DnsRecordTypeEnum.MX: 0.02
        }
    )
    domains: List[str] = Field(
        default_factory=lambda: [
            "web.internal.test",
            "db.internal.test",
            "dns.internal.test",
            "mail.internal.test",
            "example.test",
            "api.internal.test"
        ]
    )
    destinationDnsServer: str = "dns-01"

class DnsTransactionEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"dns-evt-{uuid.uuid4().hex[:8]}")
    simulationId: str = "sim-001"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: str = Field(..., min_length=1)
    destinationDevice: str = Field(..., min_length=1)
    protocol: str = "UDP"
    sourcePort: int = Field(default=53000, ge=1, le=65535)
    destinationPort: int = 53
    application: str = "DNS"
    direction: str = "OUTBOUND"
    queryType: DnsRecordTypeEnum = DnsRecordTypeEnum.A
    domain: str = Field(..., min_length=3)
    transactionId: int = Field(default=1000, ge=0, le=65535)
    isResponse: bool = False
    rcode: DnsResponseCodeEnum = DnsResponseCodeEnum.NOERROR
    answers: List[str] = Field(default_factory=list)
    ttl: int = Field(default=300, ge=0)
    bytes: int = Field(default=64, ge=12)