from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime
import json

class TargetCreate(BaseModel):
    url: str

class TargetResponse(BaseModel):
    id: int
    url: str
    domain: str
    is_verified: bool
    verification_token: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    target_url: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ScanCreate(BaseModel):
    target_url: str
    profile: str = "passive" # "passive" or "active"

class ScanResponse(BaseModel):
    id: int
    target_url: str
    profile: str
    status: str
    progress: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    domain_intel: Optional[str] = None

    class Config:
        from_attributes = True

class ScanDetailResponse(ScanResponse):
    vulnerabilities: List[VulnerabilityResponse] = []
    parsed_domain_intel: Optional[Dict[str, Any]] = None

class QuickIntelRequest(BaseModel):
    target_url: str

class QuickIntelResponse(BaseModel):
    target_url: str
    domain_intel: Dict[str, Any]
