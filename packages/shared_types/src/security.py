from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

class CIAScore(BaseModel):
    confidentiality: float = Field(default=1.0, ge=0.0, le=1.0)
    integrity: float = Field(default=1.0, ge=0.0, le=1.0)
    availability: float = Field(default=1.0, ge=0.0, le=1.0)

class VulnerabilityEntity(BaseModel):
    vuln_id: str = Field(default="VULN-001")
    cve_id: str
    name: str = "Unspecified Vulnerability"
    description: str = ""
    severity: str = "HIGH" # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: float = Field(default=7.5, ge=0.0, le=10.0)
    affected_service: str
    affected_version: str = "all"
    port: int = 0
    status: str = "OPEN"   # OPEN, MITIGATED, PATCHED, ACCEPTED, UNKNOWN
    remediation: str = "Upgrade to patched vendor release"
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AttackSurfaceExposure(BaseModel):
    exposure_tier: str = "INTERNAL"    # INTERNAL, DMZ, EXTERNAL, UNKNOWN
    accessibility: str = "RESTRICTED"   # REACHABLE, RESTRICTED, UNREACHABLE
    is_publicly_routable: bool = False
    ingress_port_count: int = 0
    open_vulnerability_count: int = 0
    exposure_multiplier: float = 0.3

class ThreatVector(BaseModel):
    threat_id: str
    name: str
    target_asset: str
    exploits_cve: Optional[str] = None
    cia_target: str
    severity: str

class AttackMapping(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    sub_technique: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    mitre_url: str