"""
DjoeraganCyber - HTML Email Vulnerability Report Generator
Sends professional security audit reports via Gmail SMTP.
"""

import smtplib
import ssl
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import List, Dict, Any, Optional


def _severity_color(severity: str) -> str:
    s = (severity or "").upper()
    if s == "CRITICAL": return "#dc2626"
    if s == "HIGH":     return "#d97706"
    if s == "MEDIUM":   return "#ca8a04"
    if s == "LOW":      return "#0284c7"
    return "#64748b"


def _grade_color(score: float, crit: int, high: int) -> str:
    if score >= 95 and crit == 0 and high == 0: return "#10b981"
    if score >= 85 and crit == 0:               return "#22c55e"
    if score >= 70 and crit == 0:               return "#0ea5e9"
    if score >= 55:                              return "#f59e0b"
    if score >= 40:                              return "#f97316"
    return "#ef4444"


def _compute_grade(score: float, crit: int, high: int) -> str:
    if score >= 95 and crit == 0 and high == 0: return "A+"
    if score >= 85 and crit == 0:               return "A"
    if score >= 70 and crit == 0:               return "B"
    if score >= 55:                              return "C"
    if score >= 40:                              return "D"
    return "F"


def build_html_email(
    scan_id: int,
    target_url: str,
    scan_time: str,
    vulnerabilities: List[Dict[str, Any]],
    recipient_email: str,
    custom_message: str = ""
) -> str:
    """
    Build a professional HTML security audit report email body.
    """
    crit   = sum(1 for v in vulnerabilities if (v.get("severity") or "").upper() == "CRITICAL")
    high   = sum(1 for v in vulnerabilities if (v.get("severity") or "").upper() == "HIGH")
    medium = sum(1 for v in vulnerabilities if (v.get("severity") or "").upper() == "MEDIUM")
    low    = sum(1 for v in vulnerabilities if (v.get("severity") or "").upper() == "LOW")
    info   = sum(1 for v in vulnerabilities if (v.get("severity") or "").upper() == "INFO")

    raw_score = max(0.0, min(100.0, 100.0 - crit*28 - high*14 - medium*6 - low*2))
    grade = _compute_grade(raw_score, crit, high)
    grade_color = _grade_color(raw_score, crit, high)

    top_findings_html = ""
    shown = 0
    for v in vulnerabilities:
        if shown >= 10:
            break
        sev = (v.get("severity") or "INFO").upper()
        sev_color = _severity_color(sev)
        title = v.get("title", "Unnamed Finding")
        desc = (v.get("description") or "")[:300]
        cwe = v.get("cwe", "")
        owasp = v.get("owasp_category", "")
        cvss = v.get("cvss_score", "")
        remediation = (v.get("remediation") or "")[:250]

        top_findings_html += f"""
        <div style="margin-bottom:16px;padding:16px;border-radius:10px;border-left:4px solid {sev_color};background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid {sev_color};">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <span style="background:{sev_color};color:white;font-size:10px;font-weight:800;padding:2px 8px;border-radius:999px;letter-spacing:1px;text-transform:uppercase;">{sev}</span>
            {'<span style="background:#e0f2fe;color:#0369a1;font-size:10px;font-weight:700;padding:2px 8px;border-radius:999px;">CVSS '+str(cvss)+'</span>' if cvss else ''}
            {'<span style="background:#f1f5f9;color:#475569;font-size:10px;padding:2px 8px;border-radius:999px;">'+owasp+'</span>' if owasp else ''}
            {'<span style="background:#f1f5f9;color:#475569;font-size:10px;padding:2px 8px;border-radius:999px;">'+cwe+'</span>' if cwe else ''}
          </div>
          <h4 style="margin:0 0 6px;font-size:13px;font-weight:700;color:#0f172a;">{title}</h4>
          <p style="margin:0 0 8px;font-size:12px;color:#475569;line-height:1.6;">{desc}{'...' if len(v.get('description','')) > 300 else ''}</p>
          {'<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:8px 12px;font-size:11px;color:#166534;"><strong>Langkah Perbaikan:</strong> '+remediation+'</div>' if remediation else ''}
        </div>
        """
        shown += 1

    remaining = max(0, len(vulnerabilities) - shown)
    remaining_note = f'<p style="text-align:center;color:#94a3b8;font-size:12px;font-style:italic;">... dan {remaining} temuan lainnya terdapat dalam laporan lengkap PDF.</p>' if remaining > 0 else ""

    custom_section = f"""
    <div style="margin:24px 0;padding:16px;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;">
      <p style="margin:0;font-size:13px;color:#92400e;line-height:1.6;"><strong>Catatan dari Auditor:</strong><br/>{custom_message}</p>
    </div>
    """ if custom_message.strip() else ""

    report_date = datetime.now().strftime("%d %B %Y, %H:%M WIB")

    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Laporan Audit Keamanan - DjoeraganCyber</title>
</head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9;">

  <!-- HEADER BANNER -->
  <div style="background:linear-gradient(135deg,#1e293b 0%,#312e81 100%);padding:40px 32px;text-align:center;">
    <div style="display:inline-block;background:white;border-radius:16px;padding:10px 20px;margin-bottom:20px;">
      <span style="font-size:18px;font-weight:900;color:#1e293b;letter-spacing:-0.5px;">DJOERAGANCYBER</span>
      <span style="font-size:10px;color:#64748b;font-weight:600;margin-left:8px;">Security Audit Platform</span>
    </div>
    <h1 style="color:white;margin:0;font-size:24px;font-weight:800;">Laporan Audit Kerentanan Website</h1>
    <p style="color:#94a3b8;margin:8px 0 0;font-size:13px;">Tanggal: {report_date} · Scan ID: #{scan_id}</p>
  </div>

  <!-- MAIN CARD -->
  <div style="max-width:700px;margin:32px auto;padding:0 16px;">

    <!-- TARGET INFO -->
    <div style="background:white;border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e2e8f0;">
      <h2 style="margin:0 0 12px;font-size:14px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:.5px;">🎯 Informasi Target Audit</h2>
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <tr><td style="padding:6px 0;color:#64748b;width:140px;">Target URL</td><td style="font-weight:700;color:#3730a3;font-family:monospace;">{target_url}</td></tr>
        <tr><td style="padding:6px 0;color:#64748b;">Waktu Scan</td><td style="color:#0f172a;">{scan_time}</td></tr>
        <tr><td style="padding:6px 0;color:#64748b;">Total Temuan</td><td style="font-weight:700;color:#0f172a;">{len(vulnerabilities)} kerentanan terdeteksi</td></tr>
        <tr><td style="padding:6px 0;color:#64748b;">Laporan Dikirim ke</td><td style="color:#0f172a;">{recipient_email}</td></tr>
      </table>
    </div>

    <!-- SECURITY GRADE CARD -->
    <div style="background:linear-gradient(135deg,{grade_color}15 0%,white 100%);border-radius:16px;padding:24px;margin-bottom:20px;border:2px solid {grade_color}40;box-shadow:0 1px 3px rgba(0,0,0,.08);">
      <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;">
        <div style="text-align:center;">
          <div style="font-size:64px;font-weight:900;color:{grade_color};line-height:1;">{grade}</div>
          <div style="font-size:11px;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:1px;">Security Grade</div>
        </div>
        <div style="flex:1;min-width:200px;">
          <div style="font-size:28px;font-weight:900;color:#0f172a;">{raw_score:.1f}<span style="font-size:16px;color:#64748b;font-weight:600;">/100</span></div>
          <div style="font-size:12px;color:#64748b;margin-bottom:16px;">Security Health Score</div>
          <!-- Stats Grid -->
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;">
            <div style="text-align:center;background:#fff1f2;border-radius:8px;padding:8px;"><div style="font-size:20px;font-weight:900;color:#dc2626;">{crit}</div><div style="font-size:9px;color:#dc2626;font-weight:700;text-transform:uppercase;">Critical</div></div>
            <div style="text-align:center;background:#fffbeb;border-radius:8px;padding:8px;"><div style="font-size:20px;font-weight:900;color:#d97706;">{high}</div><div style="font-size:9px;color:#d97706;font-weight:700;text-transform:uppercase;">High</div></div>
            <div style="text-align:center;background:#fefce8;border-radius:8px;padding:8px;"><div style="font-size:20px;font-weight:900;color:#ca8a04;">{medium}</div><div style="font-size:9px;color:#ca8a04;font-weight:700;text-transform:uppercase;">Medium</div></div>
            <div style="text-align:center;background:#f0f9ff;border-radius:8px;padding:8px;"><div style="font-size:20px;font-weight:900;color:#0284c7;">{low}</div><div style="font-size:9px;color:#0284c7;font-weight:700;text-transform:uppercase;">Low</div></div>
          </div>
        </div>
      </div>
    </div>

    {custom_section}

    <!-- FINDINGS LIST -->
    <div style="background:white;border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e2e8f0;">
      <h2 style="margin:0 0 16px;font-size:14px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:.5px;">
        ⚠️ Temuan Kerentanan {'(10 Teratas)' if len(vulnerabilities) > 10 else ''}
      </h2>
      {top_findings_html if top_findings_html else '<p style="color:#94a3b8;text-align:center;font-style:italic;">Tidak ada temuan kerentanan yang terdeteksi.</p>'}
      {remaining_note}
    </div>

    <!-- COMPLIANCE SUMMARY -->
    <div style="background:white;border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e2e8f0;">
      <h2 style="margin:0 0 16px;font-size:14px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:.5px;">🏛️ Status Kepatuhan Internasional</h2>
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead><tr style="background:#f8fafc;"><th style="text-align:left;padding:8px 12px;color:#64748b;font-weight:600;">Framework</th><th style="text-align:center;padding:8px 12px;color:#64748b;font-weight:600;">Status</th></tr></thead>
        <tbody>
          <tr style="border-top:1px solid #f1f5f9;">
            <td style="padding:10px 12px;font-weight:600;color:#0f172a;">OWASP Top 10 (2021 & 2026)</td>
            <td style="padding:10px 12px;text-align:center;"><span style="background:{'#dcfce7' if crit==0 and high==0 else '#fef9c3'};color:{'#166534' if crit==0 and high==0 else '#854d0e'};padding:2px 10px;border-radius:999px;font-weight:700;font-size:11px;">{'PARTIAL' if crit>0 or high>0 else 'COMPLIANT'}</span></td>
          </tr>
          <tr style="border-top:1px solid #f1f5f9;">
            <td style="padding:10px 12px;font-weight:600;color:#0f172a;">ISO/IEC 27001:2022 Annex A</td>
            <td style="padding:10px 12px;text-align:center;"><span style="background:{'#dcfce7' if crit==0 else '#fee2e2'};color:{'#166534' if crit==0 else '#991b1b'};padding:2px 10px;border-radius:999px;font-weight:700;font-size:11px;">{'COMPLIANT' if crit==0 else 'NON-COMPLIANT'}</span></td>
          </tr>
          <tr style="border-top:1px solid #f1f5f9;">
            <td style="padding:10px 12px;font-weight:600;color:#0f172a;">PCI-DSS v4.0 Web Security</td>
            <td style="padding:10px 12px;text-align:center;"><span style="background:{'#dcfce7' if crit==0 and high==0 else '#fee2e2'};color:{'#166534' if crit==0 and high==0 else '#991b1b'};padding:2px 10px;border-radius:999px;font-weight:700;font-size:11px;">{'COMPLIANT' if crit==0 and high==0 else 'NON-COMPLIANT'}</span></td>
          </tr>
          <tr style="border-top:1px solid #f1f5f9;">
            <td style="padding:10px 12px;font-weight:600;color:#0f172a;">NIST SP 800-53 Rev 5</td>
            <td style="padding:10px 12px;text-align:center;"><span style="background:{'#dcfce7' if raw_score>=70 else '#fef9c3'};color:{'#166534' if raw_score>=70 else '#854d0e'};padding:2px 10px;border-radius:999px;font-weight:700;font-size:11px;">{'COMPLIANT' if raw_score>=70 else 'PARTIAL'}</span></td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- RECOMMENDATIONS -->
    <div style="background:linear-gradient(135deg,#f0fdf4,white);border-radius:16px;padding:24px;margin-bottom:20px;border:1px solid #bbf7d0;box-shadow:0 1px 3px rgba(0,0,0,.08);">
      <h2 style="margin:0 0 12px;font-size:14px;font-weight:700;color:#0f172a;text-transform:uppercase;letter-spacing:.5px;">✅ Rekomendasi Tindakan Segera</h2>
      <ol style="margin:0;padding-left:20px;font-size:13px;color:#334155;line-height:2;">
        {'<li>Segera perbaiki <strong>'+str(crit)+' kerentanan Critical</strong> — risiko kompromi sistem secara langsung.</li>' if crit > 0 else ''}
        {'<li>Tangani <strong>'+str(high)+' kerentanan High</strong> dalam waktu maksimal 7 hari.</li>' if high > 0 else ''}
        {'<li>Pasang HTTP Security Headers: HSTS, CSP, X-Frame-Options, dan Referrer-Policy.</li>' if medium > 0 else ''}
        <li>Aktifkan DNSSEC dan konfigurasi SPF/DMARC untuk proteksi domain email.</li>
        <li>Lakukan re-scan setelah perbaikan untuk memverifikasi hasil hardening.</li>
        <li>Unduh laporan PDF lengkap untuk dokumentasi kepatuhan resmi.</li>
      </ol>
    </div>

    <!-- FOOTER -->
    <div style="text-align:center;padding:24px 0;color:#94a3b8;font-size:11px;border-top:1px solid #e2e8f0;">
      <p style="margin:0 0 4px;font-weight:700;color:#64748b;">DjoeraganCyber Security Audit Platform</p>
      <p style="margin:0;">Laporan ini dihasilkan secara otomatis oleh DjoeraganCyber Engine · Scan ID #{scan_id}</p>
      <p style="margin:4px 0 0;">Seluruh hasil audit bersifat rahasia dan hanya untuk penggunaan authorized security team.</p>
    </div>

  </div>
</body>
</html>"""

    return html


def send_vulnerability_report_email(
    recipient_email: str,
    subject: str,
    html_body: str,
    sender_email: Optional[str] = None,
    sender_app_password: Optional[str] = None,
    pdf_bytes: Optional[bytes] = None,
    pdf_filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send the vulnerability report via Gmail SMTP.
    Credentials read from environment variables or passed directly.

    Environment variables (preferred):
      GMAIL_SENDER_EMAIL    - Gmail address used to send
      GMAIL_APP_PASSWORD    - Gmail App Password (not your login password)
    """
    sender = sender_email or os.environ.get("GMAIL_SENDER_EMAIL", "")
    password = sender_app_password or os.environ.get("GMAIL_APP_PASSWORD", "")

    if not sender or not password:
        return {
            "success": False,
            "error": "Konfigurasi Gmail belum diatur. Tambahkan GMAIL_SENDER_EMAIL dan GMAIL_APP_PASSWORD sebagai environment variable atau isi di form pengaturan.",
            "sent_at": None
        }

    if not recipient_email or "@" not in recipient_email:
        return {
            "success": False,
            "error": f"Email penerima tidak valid: '{recipient_email}'",
            "sent_at": None
        }

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"DjoeraganCyber Security <{sender}>"
        msg["To"]      = recipient_email
        msg["X-Mailer"] = "DjoeraganCyber Security Audit Engine"
        msg["X-Priority"] = "1"

        # Plain text fallback
        plain_text = f"Laporan Audit Keamanan DjoeraganCyber\n\nEmail HTML ini memerlukan klien email modern.\n\nLihat versi HTML untuk laporan lengkap.\n\nDjoeraganCyber Security Audit Platform"
        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_body,  "html",  "utf-8"))

        # Attach PDF if provided
        if pdf_bytes and pdf_filename:
            part = MIMEBase("application", "pdf")
            part.set_payload(pdf_bytes)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={pdf_filename}")
            msg.attach(part)

        # Send via Gmail SMTP TLS
        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.login(sender, password)
            smtp.sendmail(sender, recipient_email, msg.as_string())

        sent_at = datetime.now().isoformat()
        return {
            "success": True,
            "sent_at": sent_at,
            "from": sender,
            "to": recipient_email,
            "subject": subject,
            "has_pdf_attachment": pdf_bytes is not None
        }

    except smtplib.SMTPAuthenticationError:
        return {
            "success": False,
            "error": "Autentikasi Gmail gagal. Pastikan Gmail App Password benar dan 2FA sudah aktif di akun Google Anda.",
            "sent_at": None
        }
    except smtplib.SMTPRecipientsRefused as e:
        return {
            "success": False,
            "error": f"Email penerima ditolak oleh server Gmail: {str(e)}",
            "sent_at": None
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Gagal mengirim email: {str(e)}",
            "sent_at": None
        }
