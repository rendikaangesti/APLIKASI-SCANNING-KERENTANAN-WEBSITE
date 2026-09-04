from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import List, Dict, Any
import json

from app.core.database import get_db
from app.models.scan import Scan, Target, Vulnerability
from app.schemas.scan import (
    ScanCreate, ScanResponse, ScanDetailResponse, VulnerabilityResponse,
    QuickIntelRequest, QuickIntelResponse
)
from app.core.ssrf_guard import validate_and_sanitize_target
from app.engine.tasks import run_scan_pipeline
from app.engine.passive.domain_relations import DomainRelationsAnalyzer
from app.engine.scoring.compliance_benchmark import InternationalComplianceEngine

router = APIRouter()

@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    # 1. Anti-SSRF Validation
    is_valid, normalized_url, err_msg = validate_and_sanitize_target(payload.target_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    # 2. Check/Associate Target
    res = await db.execute(select(Target).where(Target.url == normalized_url))
    target = res.scalar_one_or_none()

    # 3. Create Scan Record
    new_scan = Scan(
        target_id=target.id if target else None,
        target_url=normalized_url,
        profile=payload.profile.lower(),
        status="QUEUED",
        progress=0
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # 4. Dispatch Asynchronous Background Worker Task
    background_tasks.add_task(run_scan_pipeline, new_scan.id, normalized_url, payload.profile)

    return new_scan

@router.get("/", response_model=List[ScanResponse])
async def list_scans(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).order_by(Scan.started_at.desc()))
    return res.scalars().all()

@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_detail(scan_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")
    
    # Parse domain intel if present
    parsed_intel = None
    if scan.domain_intel:
        try:
            parsed_intel = json.loads(scan.domain_intel)
        except Exception:
            parsed_intel = None

    response_data = ScanDetailResponse.model_validate(scan)
    response_data.parsed_domain_intel = parsed_intel
    return response_data

@router.get("/{scan_id}/domain-intel")
async def get_scan_domain_intel(scan_id: int, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """
    Mengambil data intelijen relasi domain & SSL untuk scan tertentu.
    """
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")
    
    if not scan.domain_intel:
        return {"status": "pending", "message": "Data domain & SSL intelligence belum tersedia atau scan masih berlangsung."}
    
    try:
        return json.loads(scan.domain_intel)
    except Exception:
        return {"raw": scan.domain_intel}

@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_scan_vulnerabilities(scan_id: int, severity: str = None, db: AsyncSession = Depends(get_db)):
    query = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.where(Vulnerability.severity == severity.capitalize())
    
    query = query.order_by(Vulnerability.cvss_score.desc())
    res = await db.execute(query)
    return res.scalars().all()

@router.post("/quick-intel", response_model=QuickIntelResponse)
async def analyze_quick_domain_intel(payload: QuickIntelRequest):
    """
    Endpoint mandiri untuk menganalisis keterhubungan domain/SSL dan histori CT logs secara instan.
    """
    is_valid, normalized_url, err_msg = validate_and_sanitize_target(payload.target_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    analyzer = DomainRelationsAnalyzer()
    results = await analyzer.analyze(normalized_url)
    
    return {
        "target_url": normalized_url,
        "domain_intel": results
    }

@router.get("/{scan_id}/compliance")
async def get_scan_compliance_audit(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Menghitung evaluasi kepatuhan standar internasional (OWASP, ISO 27001, PCI-DSS, NIST) untuk scan tertentu.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    vulns_data = [{
        "title": v.title,
        "severity": v.severity,
        "owasp_category": v.owasp_category
    } for v in scan.vulnerabilities]

    compliance = InternationalComplianceEngine.evaluate_compliance(vulns_data)
    scorecard = InternationalComplianceEngine.calculate_scorecard(vulns_data)

    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "scorecard": scorecard,
        "compliance": compliance
    }

