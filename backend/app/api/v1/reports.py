from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import os
import io
import csv
import sqlite3
import tempfile
import json
import shutil
from datetime import datetime

from app.core.database import get_db
from app.models.scan import Scan, Vulnerability
from app.engine.reporting.pdf_generator import PDFReportGenerator
from app.engine.reporting.email_reporter import build_html_email, send_vulnerability_report_email

router = APIRouter()

@router.get("/{scan_id}/pdf")
async def download_pdf_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Menghasilkan dan mengunduh laporan audit keamanan PDF profesional.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    scan_data = {
        "target_url": scan.target_url,
        "profile": scan.profile,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at
    }

    findings = [
        {
            "title": v.title,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "cvss_vector": v.cvss_vector,
            "owasp_category": v.owasp_category,
            "cwe": v.cwe,
            "description": v.description,
            "remediation": v.remediation,
            "evidence": v.evidence,
            "target_url": v.target_url
        }
        for v in scan.vulnerabilities
    ]

    domain_intel_data = None
    if scan.domain_intel:
        try:
            domain_intel_data = json.loads(scan.domain_intel)
        except Exception:
            domain_intel_data = None

    temp_dir = tempfile.gettempdir()
    output_pdf_path = os.path.join(temp_dir, f"Security_Report_Scan_{scan.id}.pdf")

    try:
        PDFReportGenerator.generate_report(scan_data, findings, output_pdf_path, domain_intel=domain_intel_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal generate PDF report: {str(e)}")

    clean_filename = f"DjoeraganCyber_Audit_Report_Scan_{scan.id}.pdf"
    return FileResponse(
        path=output_pdf_path,
        media_type="application/pdf",
        filename=clean_filename
    )

@router.get("/{scan_id}/sarif")
async def export_sarif_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Mengunduh hasil audit dalam format standar industri SARIF 2.1.0 untuk integrasi DevSecOps & CI/CD.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    rules = []
    results = []
    seen_rules = set()

    for v in scan.vulnerabilities:
        rule_id = f"VH-{v.cwe or 'VULN'}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": v.title,
                "shortDescription": {"text": v.title},
                "fullDescription": {"text": v.description or v.title},
                "helpUri": "https://owasp.org/Top10/",
                "properties": {
                    "tags": ["security", v.owasp_category or "web-vulnerability"],
                    "precision": "high",
                    "problem.severity": "error" if v.severity in ("Critical", "High") else "warning"
                }
            })

        level = "error" if v.severity in ("Critical", "High") else ("warning" if v.severity == "Medium" else "note")
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"[{v.severity}] {v.title}: {v.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.target_url or scan.target_url}
                }
            }],
            "properties": {
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "remediation": v.remediation,
                "evidence": v.evidence
            }
        })

    sarif_data = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DjoeraganCyber Live Engine",
                    "version": "2.0.0",
                    "informationUri": "https://djoeragancyber.com",
                    "rules": rules
                }
            },
            "results": results
        }]
    }

    return JSONResponse(
        content=sarif_data,
        headers={"Content-Disposition": f"attachment; filename=DjoeraganCyber_Scan_{scan.id}.sarif"}
    )

@router.get("/{scan_id}/json")
async def export_json_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Mengunduh raw structured JSON data dari seluruh hasil scan.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    data = {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "profile": scan.profile,
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": {
            "total_findings": scan.total_findings,
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count
        },
        "findings": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "owasp_category": v.owasp_category,
                "cwe": v.cwe,
                "description": v.description,
                "remediation": v.remediation,
                "evidence": v.evidence,
                "target_url": v.target_url
            }
            for v in scan.vulnerabilities
        ]
    }

    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f"attachment; filename=DjoeraganCyber_Scan_{scan.id}.json"}
    )

@router.get("/{scan_id}/csv")
async def export_csv_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Mengunduh daftar temuan kerentanan dalam format CSV untuk spreadsheet / Excel.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Severity", "CVSS Score", "CVSS Vector",
        "OWASP Category", "CWE", "Target URL", "Description", "Remediation", "Evidence"
    ])

    for v in scan.vulnerabilities:
        writer.writerow([
            v.id,
            v.title,
            v.severity,
            v.cvss_score,
            v.cvss_vector or "",
            v.owasp_category or "",
            v.cwe or "",
            v.target_url or scan.target_url,
            v.description or "",
            v.remediation or "",
            v.evidence or ""
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=DjoeraganCyber_Scan_{scan.id}.csv"}
    )

@router.get("/{scan_id}/sqlite")
async def export_sqlite_database(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Mengekspor seluruh data hasil scan ke dalam file SQLite Database yang dapat diunduh.
    Berisi tabel: scan_info, vulnerabilities, metadata, dan timeline log.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    # Create temp SQLite file
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, f"DjoeraganCyber_Scan_{scan.id}.db")

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # --- Table: scan_info ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_info (
                id INTEGER PRIMARY KEY,
                target_url TEXT,
                profile TEXT,
                status TEXT,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                info_count INTEGER,
                started_at TEXT,
                completed_at TEXT,
                exported_at TEXT,
                exported_by TEXT
            )
        """)
        cur.execute("""
            INSERT INTO scan_info VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan.id,
            scan.target_url,
            scan.profile,
            scan.status,
            scan.total_findings or 0,
            scan.critical_count or 0,
            scan.high_count or 0,
            scan.medium_count or 0,
            scan.low_count or 0,
            scan.info_count or 0,
            scan.started_at.isoformat() if scan.started_at else None,
            scan.completed_at.isoformat() if scan.completed_at else None,
            datetime.utcnow().isoformat(),
            "DjoeraganCyber Security Audit Platform"
        ))

        # --- Table: vulnerabilities ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                title TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                owasp_category TEXT,
                cwe TEXT,
                description TEXT,
                remediation TEXT,
                evidence TEXT,
                target_url TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_info(id)
            )
        """)
        for v in scan.vulnerabilities:
            cur.execute("""
                INSERT INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                v.id,
                scan.id,
                v.title,
                v.severity,
                v.cvss_score,
                v.cvss_vector or "",
                v.owasp_category or "",
                v.cwe or "",
                v.description or "",
                v.remediation or "",
                v.evidence or "",
                v.target_url or scan.target_url
            ))

        # --- Table: domain_intel ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS domain_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                data_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_info(id)
            )
        """)
        if scan.domain_intel:
            cur.execute("INSERT INTO domain_intel (scan_id, data_json) VALUES (?, ?)",
                        (scan.id, scan.domain_intel))

        # --- Table: severity_summary ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS severity_summary (
                scan_id INTEGER,
                severity TEXT,
                count INTEGER,
                percentage REAL
            )
        """)
        total = scan.total_findings or 1
        for sev, cnt in [
            ("CRITICAL", scan.critical_count or 0),
            ("HIGH", scan.high_count or 0),
            ("MEDIUM", scan.medium_count or 0),
            ("LOW", scan.low_count or 0),
            ("INFO", scan.info_count or 0),
        ]:
            cur.execute("INSERT INTO severity_summary VALUES (?, ?, ?, ?)",
                        (scan.id, sev, cnt, round(cnt / total * 100, 2)))

        # --- Table: export_metadata ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS export_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        meta = [
            ("tool", "DjoeraganCyber Web & API Security Suite"),
            ("version", "2.0.0"),
            ("export_format", "SQLite Database v3"),
            ("schema_version", "1.0"),
            ("export_date", datetime.utcnow().isoformat()),
            ("target", scan.target_url),
            ("scan_profile", scan.profile),
            ("owasp_standard", "OWASP Top 10 (2026 Ready)"),
            ("cvss_standard", "CVSS v3.1"),
        ]
        cur.executemany("INSERT INTO export_metadata VALUES (?, ?)", meta)

        conn.commit()
        conn.close()

        # Read file into bytes and clean up
        with open(db_path, "rb") as f:
            db_bytes = f.read()
        shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Gagal membuat SQLite export: {str(e)}")

    return Response(
        content=db_bytes,
        media_type="application/x-sqlite3",
        headers={"Content-Disposition": f"attachment; filename=DjoeraganCyber_Scan_{scan.id}.db"}
    )


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL REPORT ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────

class EmailReportRequest(BaseModel):
    recipient_email: str = Field(..., description="Alamat email penerima laporan")
    subject: Optional[str] = Field(None, description="Subject email (opsional)")
    custom_message: Optional[str] = Field("", description="Pesan tambahan dari auditor")
    attach_pdf: Optional[bool] = Field(False, description="Sertakan PDF sebagai lampiran")
    sender_email: Optional[str] = Field(None, description="Gmail pengirim (opsional, gunakan env var GMAIL_SENDER_EMAIL)")
    sender_app_password: Optional[str] = Field(None, description="Gmail App Password (opsional, gunakan env var GMAIL_APP_PASSWORD)")


@router.post("/{scan_id}/email")
async def send_email_report(
    scan_id: int,
    payload: EmailReportRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Kirim laporan kerentanan lengkap via Gmail SMTP ke alamat email yang ditentukan.
    Mendukung lampiran PDF opsional.
    """
    # 1. Fetch scan + vulnerabilities
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID #{scan_id} tidak ditemukan.")

    if scan.status not in ("COMPLETED", "DONE"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan belum selesai (status: {scan.status}). Tunggu hingga scan completed sebelum mengirim laporan."
        )

    # 2. Build vulnerabilities list
    vulns = [
        {
            "title": v.title,
            "severity": v.severity,
            "description": v.description,
            "remediation": v.remediation,
            "owasp_category": v.owasp_category,
            "cwe": v.cwe,
            "cvss_score": v.cvss_score,
            "target_url": v.target_url,
            "evidence": v.evidence,
        }
        for v in scan.vulnerabilities
    ]

    # 3. Build HTML email body
    scan_time = scan.started_at.strftime("%d %B %Y, %H:%M UTC") if scan.started_at else datetime.utcnow().strftime("%d %B %Y, %H:%M UTC")
    subject = payload.subject or f"[DjoeraganCyber] Laporan Audit Keamanan - {scan.target_url}"

    html_body = build_html_email(
        scan_id=scan_id,
        target_url=scan.target_url,
        scan_time=scan_time,
        vulnerabilities=vulns,
        recipient_email=payload.recipient_email,
        custom_message=payload.custom_message or ""
    )

    # 4. Optionally generate PDF attachment
    pdf_bytes = None
    pdf_filename = None
    if payload.attach_pdf:
        try:
            scan_dict = {
                "target_url": scan.target_url,
                "profile": scan.profile,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at
            }
            intel_dict = json.loads(scan.domain_intel) if scan.domain_intel else None
            pdf_bytes = await run_in_threadpool(
                PDFReportGenerator.generate_bytes,
                scan_dict,
                vulns,
                intel_dict
            )
            pdf_filename = f"DjoeraganCyber_Report_{scan_id}.pdf"
        except Exception as pdf_err:
            pdf_bytes = None


    # 5. Send email via Gmail SMTP in thread pool (blocking IO)
    result = await run_in_threadpool(
        send_vulnerability_report_email,
        payload.recipient_email,
        subject,
        html_body,
        payload.sender_email,
        payload.sender_app_password,
        pdf_bytes,
        pdf_filename
    )

    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Gagal mengirim email."))

    return {
        "success": True,
        "message": f"Laporan berhasil dikirim ke {payload.recipient_email}.",
        "sent_at": result.get("sent_at"),
        "subject": subject,
        "findings_count": len(vulns),
        "has_pdf_attachment": pdf_bytes is not None
    }
