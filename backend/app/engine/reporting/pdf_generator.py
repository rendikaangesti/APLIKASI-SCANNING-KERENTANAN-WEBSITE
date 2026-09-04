import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header
        self.drawString(54, 792 - 36, "CONFIDENTIAL - WEB VULNERABILITY AUDIT REPORT")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 792 - 42, 612 - 54, 792 - 42)
        
        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 36, page_text)
        self.drawString(54, 36, "Standards: OWASP Top 10 (2021) • CVSS v3.1 Scoring")
        self.line(54, 48, 612 - 54, 48)
        self.restoreState()

class PDFReportGenerator:
    """
    Generator Laporan Audit Keamanan Web Standar Enterprise dalam format PDF.
    """

    @classmethod
    def generate_report(
        cls, 
        scan_data: Dict[str, Any], 
        findings: List[Dict[str, Any]], 
        output_path: str,
        domain_intel: Optional[Dict[str, Any]] = None
    ):
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#0f172a")
        )
        
        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#64748b")
        )
        
        h2_style = ParagraphStyle(
            'Heading2_Custom',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'Body_Custom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155")
        )

        code_style = ParagraphStyle(
            'Code_Custom',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0f172a")
        )

        elements = []

        # ================= COVER & HEADER =================
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("SECURITY AUDIT & ASSESSMENT REPORT", subtitle_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("Web Application Vulnerability Assessment", title_style))
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=14))

        # Target Summary Metadata Box
        target_info = [
            [Paragraph("<b>Target URL:</b>", body_style), Paragraph(scan_data.get("target_url", "-"), body_style)],
            [Paragraph("<b>Scan Profile:</b>", body_style), Paragraph(scan_data.get("profile", "Passive").upper(), body_style)],
            [Paragraph("<b>Audit Date:</b>", body_style), Paragraph(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)],
            [Paragraph("<b>Compliance Standards:</b>", body_style), Paragraph("OWASP Top 10 (2021), CVSS v3.1, NIST SP 800-115", body_style)],
        ]
        info_table = Table(target_info, colWidths=[130, 374])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 16))

        # ================= EXECUTIVE SUMMARY =================
        elements.append(Paragraph("1. Executive Summary", h2_style))
        summary_text = (
            f"Laporan audit keamanan ini disusun berdasarkan hasil pemindaian otomatis terhadap target "
            f"<b>{scan_data.get('target_url')}</b>. Pengujian dilakukan untuk mengidentifikasi potensi kelemahan "
            f"konfigurasi, kerentanan injeksi, eksposur informasi sensitif, dan implementasi kriptografi. "
            f"Total ditemukan <b>{len(findings)}</b> temuan keamanan dengan perincian tingkat keparahan (severity) "
            f"sebagaimana dirangkum pada matriks risiko di bawah ini."
        )
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 10))

        # Severity Matrix Table
        crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        med_count = sum(1 for f in findings if f.get("severity") == "Medium")
        low_count = sum(1 for f in findings if f.get("severity") == "Low")
        info_count = sum(1 for f in findings if f.get("severity") == "Info")

        matrix_data = [
            ["Critical (9.0-10.0)", "High (7.0-8.9)", "Medium (4.0-6.9)", "Low (0.1-3.9)", "Informational"],
            [str(crit_count), str(high_count), str(med_count), str(low_count), str(info_count)]
        ]
        matrix_table = Table(matrix_data, colWidths=[100, 100, 100, 100, 104])
        matrix_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor("#ef4444")),
            ('BACKGROUND', (1,0), (1,0), colors.HexColor("#f97316")),
            ('BACKGROUND', (2,0), (2,0), colors.HexColor("#eab308")),
            ('BACKGROUND', (3,0), (3,0), colors.HexColor("#3b82f6")),
            ('BACKGROUND', (4,0), (4,0), colors.HexColor("#64748b")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,1), (-1,1), 14),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#f1f5f9")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(matrix_table)
        elements.append(Spacer(1, 18))

        # ================= DETAILED FINDINGS =================
        elements.append(Paragraph("2. Detailed Technical Findings & Remediation", h2_style))
        elements.append(Paragraph("Berikut adalah rincian setiap temuan lengkap dengan kategori OWASP, CWE, dampak, dan rekomendasi perbaikan:", body_style))
        elements.append(Spacer(1, 8))

        if not findings:
            elements.append(Paragraph("<i>Tidak ditemukan kerentanan berisiko pada pemindaian ini.</i>", body_style))
        else:
            for idx, item in enumerate(findings, 1):
                sev = item.get("severity", "Medium")
                sev_color = {
                    "Critical": "#ef4444",
                    "High": "#f97316",
                    "Medium": "#eab308",
                    "Low": "#3b82f6",
                    "Info": "#64748b"
                }.get(sev, "#64748b")

                finding_box = [
                    [
                        Paragraph(f"<b>#{idx} {item.get('title')}</b>", ParagraphStyle('FTitle', parent=body_style, fontName='Helvetica-Bold', textColor=colors.HexColor("#0f172a"))),
                        Paragraph(f"<font color='{sev_color}'><b>[{sev.upper()}] - CVSS {item.get('cvss_score', '-')}</b></font>", ParagraphStyle('FSev', parent=body_style, alignment=2))
                    ],
                    [
                        Paragraph(f"<b>OWASP:</b> {item.get('owasp_category', '-')} &nbsp;|&nbsp; <b>CWE:</b> {item.get('cwe', '-')}", body_style),
                        ""
                    ],
                    [
                        Paragraph(f"<b>Description:</b> {item.get('description', '-')}", body_style),
                        ""
                    ],
                    [
                        Paragraph(f"<b>Remediation Guide:</b><br/>{item.get('remediation', '-')}", ParagraphStyle('FRem', parent=body_style, textColor=colors.HexColor("#047857"))),
                        ""
                    ],
                ]

                if item.get("evidence"):
                    finding_box.append([
                        Paragraph(f"<b>Evidence / Proof:</b><br/><font face='Courier' color='#334155'>{item.get('evidence')}</font>", code_style),
                        ""
                    ])

                f_table = Table(finding_box, colWidths=[380, 124])
                f_table.setStyle(TableStyle([
                    ('SPAN', (0,1), (1,1)),
                    ('SPAN', (0,2), (1,2)),
                    ('SPAN', (0,3), (1,3)),
                    *([('SPAN', (0,4), (1,4))] if len(finding_box) > 4 else []),
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ffffff")),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor(sev_color)),
                    ('LINEBELOW', (0,0), (-1,0), 0.5, colors.HexColor("#e2e8f0")),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))

                elements.append(KeepTogether([f_table, Spacer(1, 10)]))

        # ================= DOMAIN & SSL RELATIONS & HISTORY =================
        if domain_intel:
            elements.append(Spacer(1, 14))
            elements.append(Paragraph("3. Domain & SSL Relationship & Historical Intelligence", h2_style))
            elements.append(Paragraph(
                "Pemeriksaan asosiasi domain, Subject Alternative Names (SANs) sertifikat aktif, dan histori Certificate Transparency (CT Logs) untuk mendeteksi hubungan dengan website lain:",
                body_style
            ))
            elements.append(Spacer(1, 8))

            curr_ssl = domain_intel.get("current_ssl", {})
            is_shared = domain_intel.get("is_shared_ssl", False)
            cross_domains = domain_intel.get("cross_website_domains", [])
            san_domains = domain_intel.get("san_domains", [])
            ptr_hosts = domain_intel.get("reverse_ptr_hosts", [])
            ip_addresses = domain_intel.get("ip_addresses", [])
            ct_certs = domain_intel.get("historical_certificates", [])
            hist_subs = domain_intel.get("historical_subdomains", [])

            intel_overview = [
                [Paragraph("<b>Root Domain:</b>", body_style), Paragraph(domain_intel.get("root_domain", "-"), body_style)],
                [Paragraph("<b>SSL Issuer:</b>", body_style), Paragraph(str(curr_ssl.get("issuer") or "-"), body_style)],
                [Paragraph("<b>SSL Multi-Domain Sharing:</b>", body_style), Paragraph(
                    "<font color='#dc2626'><b>⚠️ Shared SSL dengan Website Lain Terdeteksi</b></font>" if is_shared else "<font color='#16a34a'><b>Dedicated / Single Organization SSL</b></font>",
                    body_style
                )],
                [Paragraph("<b>Active SAN Domains:</b>", body_style), Paragraph(f"{len(san_domains)} domains/subdomains", body_style)],
                [Paragraph("<b>Associated IP & PTR:</b>", body_style), Paragraph(f"{', '.join(ip_addresses) if ip_addresses else '-'} (PTR: {', '.join(ptr_hosts) if ptr_hosts else 'None'})", body_style)],
            ]

            intel_table = Table(intel_overview, colWidths=[140, 364])
            intel_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
                ('PADDING', (0,0), (-1,-1), 5),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(intel_table)
            elements.append(Spacer(1, 10))

            if cross_domains:
                elements.append(Paragraph("<b>External Domains Sharing Current SSL (Cross-Website Association):</b>", body_style))
                elements.append(Paragraph(f"<font color='#b91c1c'>{', '.join(cross_domains)}</font>", code_style))
                elements.append(Spacer(1, 8))

            if hist_subs:
                elements.append(Paragraph(f"<b>Historical Subdomains Discovered from CT Logs ({len(hist_subs)} items):</b>", body_style))
                elements.append(Paragraph(", ".join(hist_subs[:30]) + ("..." if len(hist_subs) > 30 else ""), code_style))
                elements.append(Spacer(1, 8))

            if ct_certs:
                elements.append(Paragraph("<b>Certificate Transparency (CT Logs) Issuance History:</b>", body_style))
                ct_rows = [["Logged At", "Issuer", "Common Name", "Valid Period"]]
                for c in ct_certs[:6]:
                    valid_p = f"{c.get('not_before', '')[:10]} - {c.get('not_after', '')[:10]}"
                    ct_rows.append([
                        c.get("logged_at", "")[:10],
                        c.get("issuer", "")[:25],
                        c.get("common_name", "")[:30],
                        valid_p
                    ])
                ct_table = Table(ct_rows, colWidths=[80, 140, 160, 124])
                ct_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                    ('PADDING', (0,0), (-1,-1), 4),
                ]))
                elements.append(ct_table)

        doc.build(elements, canvasmaker=NumberedCanvas)
        return output_path

    @classmethod
    def generate_bytes(
        cls,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        domain_intel: Optional[Dict[str, Any]] = None
    ) -> bytes:
        import tempfile
        import shutil
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "report.pdf")
        try:
            cls.generate_report(scan_data, findings, temp_file, domain_intel=domain_intel)
            with open(temp_file, "rb") as f:
                return f.read()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

