from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any, List
from app.schemas.live import (
    LiveTerminalRequest, LiveTerminalResponse,
    LiveExploreRequest, LiveExploreResponse,
    LiveVerifyRequest, LiveVerifyResponse,
    TargetEmailDetectRequest, TargetEmailDetectResponse,
    LiveInputTestRequest, LiveInputTestResponse,
    LiveDBBoundaryRequest, LiveDBBoundaryResponse
)
from app.engine.live.live_engine import LiveAuditEngine
from app.engine.passive.email_finder import TargetEmailDetector
from app.core.ssrf_guard import validate_and_sanitize_target

router = APIRouter()

@router.post("/terminal-exec", response_model=LiveTerminalResponse)
async def execute_live_terminal(payload: LiveTerminalRequest):
    """
    Mengeksekusi perintah audit keamanan secara LIVE terhadap target domain.
    """
    res = await LiveAuditEngine.execute_live_command(
        command=payload.command,
        target_url=payload.target_url
    )
    return LiveTerminalResponse(
        command=res.get("command", payload.command),
        output=res.get("output", ""),
        exit_code=res.get("exit_code", 0),
        prompt="auditor@live-target:~$ ",
        timestamp=res.get("timestamp", "")
    )

@router.post("/explore", response_model=LiveExploreResponse)
async def explore_live_assets(payload: LiveExploreRequest):
    """
    Mengeksplorasi aset target domain secara LIVE: crawling endpoint,
    matrix status file sensitif, security headers, WAF, dan open ports.
    """
    res = await LiveAuditEngine.get_live_asset_explorer(
        target_url=payload.target_url,
        scan_id=payload.scan_id
    )
    return res

@router.post("/verify-poc", response_model=LiveVerifyResponse)
async def verify_finding_poc(payload: LiveVerifyRequest):
    """
    Melakukan verifikasi Proof-of-Concept (PoC) temuan kerentanan secara LIVE.
    """
    res = await LiveAuditEngine.verify_finding_live(
        target_url=payload.target_url,
        finding_title=payload.finding_title,
        evidence=payload.evidence or ""
    )
    return res

@router.post("/detect-email", response_model=TargetEmailDetectResponse)
async def detect_website_email(payload: TargetEmailDetectRequest):
    """
    Mendeteksi secara cerdas dan otomatis alamat email / Gmail kontak resmi,
    file security.txt RFC 9116, dan Google Workspace MX dari target website yang diaudit.
    """
    is_valid, normalized_url, err_msg = validate_and_sanitize_target(payload.target_url)
    target = normalized_url if is_valid else payload.target_url
    res = await TargetEmailDetector.detect(target)
    return TargetEmailDetectResponse(**res)

@router.post("/test-input", response_model=LiveInputTestResponse)
async def test_input_resilience(payload: LiveInputTestRequest):
    """
    Menjalankan pengujian ketahanan kolom masukan & kotak pencarian secara LIVE.
    """
    res = await LiveAuditEngine.run_live_input_test(
        target_url=payload.target_url,
        param_name=payload.param_name,
        probe=payload.probe,
        method=payload.method
    )
    return LiveInputTestResponse(**res)

@router.post("/test-db-boundary", response_model=LiveDBBoundaryResponse)
async def test_db_boundary(payload: LiveDBBoundaryRequest):
    """
    Menjalankan simulasi instruksi manipulasi batas struktur data (DDL) dalam mode terisolasi.
    """
    res = await LiveAuditEngine.run_live_db_boundary(
        target_url=payload.target_url,
        param_name=payload.param_name,
        instruction_id=payload.instruction_id,
        method=payload.method
    )
    return LiveDBBoundaryResponse(**res)


