from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class LiveTerminalRequest(BaseModel):
    command: str
    target_url: str = "https://example.com"

class LiveTerminalResponse(BaseModel):
    command: str
    output: str
    exit_code: int = 0
    prompt: str = "auditor@live-target:~$ "
    timestamp: str

class LiveExploreRequest(BaseModel):
    target_url: str
    scan_id: Optional[int] = None

class LiveExploreResponse(BaseModel):
    target_url: str
    target_hostname: str
    timestamp: str
    discovered_urls: List[str] = []
    discovered_forms: List[Dict[str, Any]] = []
    sensitive_paths_matrix: List[Dict[str, Any]] = []
    header_findings: List[Dict[str, Any]] = []
    waf_summary: str = ""
    ports_summary: str = ""

class LiveVerifyRequest(BaseModel):
    target_url: str
    finding_title: str
    evidence: Optional[str] = ""

class LiveVerifyResponse(BaseModel):
    verified: bool
    target_url: str
    finding_title: str
    status_code: int
    latency_ms: int
    request_raw: str
    response_headers: str
    response_body_snippet: str
    timestamp: str
    message: str


class TargetEmailDetectRequest(BaseModel):
    target_url: str
    scan_id: Optional[int] = None


class TargetEmailDetectResponse(BaseModel):
    target_url: str
    target_hostname: str
    primary_email: str
    detected_emails: List[str] = []
    all_suggestions: List[str] = []
    has_gmail: bool = False
    gmail_addresses: List[str] = []
    is_google_workspace: bool = False
    source: str
    source_label: str

class LiveInputTestRequest(BaseModel):
    target_url: str
    param_name: str
    probe: str
    method: str = "GET"

class LiveInputTestResponse(BaseModel):
    target_url: str
    param: str
    probe: str
    method: str
    status_code: int
    response_length: int
    db_error_found: bool
    matched_engine: Optional[str] = None
    matched_pattern: Optional[str] = None
    is_blocked_by_waf: bool
    is_reflected_raw: bool
    resilience_status: str
    score_impact: str
    timestamp: str

class LiveDBBoundaryRequest(BaseModel):
    target_url: str
    param_name: str = "id"
    instruction_id: str = "drop_database_canary" # 'drop_database_canary' | 'drop_table_canary' | 'truncate_table_canary' | 'alter_table_canary'
    method: str = "GET"
    is_isolated_confirmed: bool = True

class LiveDBBoundaryResponse(BaseModel):
    target_url: str
    param_tested: str
    instruction_type: str
    risk_category: str
    payload_used: str
    safe_target: str
    status_code: int
    status_type: str
    verdict: str
    severity: str
    waf_blocked: bool
    stacked_blocked: bool
    privilege_denied: bool
    syntax_error: bool
    hardening_script: str
    timestamp: str

