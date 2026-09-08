from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class HttpMethodEnum(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"

class WebProtocolEnum(str, Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"

class WebTrafficProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"wprof-{uuid.uuid4().hex[:6]}")
    name: str = "Standard-Web-Browsing"
    protocol: WebProtocolEnum = WebProtocolEnum.HTTPS
    destinationPort: int = Field(default=443, ge=1, le=65535)
    requestRate: float = Field(default=2.0, ge=0.1, le=500.0, description="Requests per second")
    requestSizeMean: int = Field(default=450, ge=64, description="Average HTTP request size in bytes")
    responseSizeMean: int = Field(default=2500, ge=128, description="Average HTTP response size in bytes")
    statusDistribution: Dict[int, float] = Field(
        default_factory=lambda: {200: 0.90, 301: 0.03, 404: 0.05, 500: 0.02}
    )
    paths: List[str] = Field(
        default_factory=lambda: ["/", "/products", "/about", "/api/v1/status", "/login"]
    )
    destination: str = "web-01"
    duration: int = Field(default=60, ge=1)

    @field_validator("destinationPort")
    @classmethod
    def validate_port_matches_proto(cls, v: int, info) -> int:
        proto = info.data.get("protocol")
        if proto == WebProtocolEnum.HTTP and v == 443:
            return 80
        if proto == WebProtocolEnum.HTTPS and v == 80:
            return 443
        return v

class HttpTransactionEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"web-evt-{uuid.uuid4().hex[:8]}")
    simulationId: str = "sim-001"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: str = Field(..., min_length=1)
    destinationDevice: str = Field(..., min_length=1)
    protocol: WebProtocolEnum
    destinationPort: int
    application: str = "WEB"
    direction: str = "OUTBOUND"
    method: HttpMethodEnum = HttpMethodEnum.GET
    path: str = "/"
    statusCode: int = 200
    requestBytes: int = Field(default=350, ge=64)
    responseBytes: int = Field(default=1200, ge=0)
    isEncrypted: bool = False
    tlsVersion: Optional[str] = None