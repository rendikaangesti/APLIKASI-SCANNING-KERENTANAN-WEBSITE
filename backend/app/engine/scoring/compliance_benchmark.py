"""
International Security Standards Compliance & Posture Scorecard Engine
Conforms to:
- OWASP Top 10 (2021 & 2026 Standards)
- ISO/IEC 27001:2022 Control Annex A
- PCI-DSS v4.0 (Req 6.4, Req 11.3)
- NIST SP 800-53 Rev 5 (SI, SC, AC Controls)
- CIS Web Server Benchmark
"""

from typing import Dict, Any, List

class InternationalComplianceEngine:
    """
    Enterprise-grade security posture evaluator and international compliance mapping engine.
    """

    @classmethod
    def calculate_scorecard(cls, findings: List[Dict[str, Any]] = None, stats: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Calculates letter grade (A+ to F), numeric security posture score (0-100),
        and multi-dimensional pillar ratings.
        """
        findings = findings or []
        
        # Count findings by severity
        crit_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
        high_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
        med_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "MEDIUM")
        low_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "LOW")
        info_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "INFO")

        # Base score 100
        score = 100.0
        score -= crit_count * 28.0
        score -= high_count * 14.0
        score -= med_count * 6.0
        score -= low_count * 2.0
        score = max(0.0, min(100.0, round(score, 1)))

        # Determine letter grade
        if score >= 95 and crit_count == 0 and high_count == 0:
            grade = "A+"
            grade_color = "#10b981"
            risk_label = "Sangat Rendah (Hardened)"
        elif score >= 85 and crit_count == 0:
            grade = "A"
            grade_color = "#22c55e"
            risk_label = "Rendah (Secure)"
        elif score >= 70 and crit_count == 0:
            grade = "B"
            grade_color = "#0ea5e9"
            risk_label = "Moderat (Acceptable)"
        elif score >= 55:
            grade = "C"
            grade_color = "#f59e0b"
            risk_label = "Perhatian (Elevated Risk)"
        elif score >= 40:
            grade = "D"
            grade_color = "#f97316"
            risk_label = "Tinggi (High Vulnerability)"
        else:
            grade = "F"
            grade_color = "#ef4444"
            risk_label = "Kritis (Severely Compromised)"

        # Pillar ratings (0-100)
        has_ssl_issue = any("ssl" in (f.get("title") or "").lower() or "tls" in (f.get("title") or "").lower() for f in findings)
        has_header_issue = any("header" in (f.get("title") or "").lower() or "csp" in (f.get("title") or "").lower() or "hsts" in (f.get("title") or "").lower() for f in findings)
        has_injection_issue = any("injection" in (f.get("title") or "").lower() or "xss" in (f.get("title") or "").lower() or "sqli" in (f.get("title") or "").lower() for f in findings)
        has_sensitive_issue = any(".env" in (f.get("title") or "").lower() or "secret" in (f.get("title") or "").lower() or "git" in (f.get("title") or "").lower() for f in findings)

        pillars = {
            "cryptography_tls": max(20, 100 - (40 if has_ssl_issue else 0)),
            "web_hardening": max(20, 100 - (35 if has_header_issue else 0) - (low_count * 5)),
            "application_integrity": max(10, 100 - (50 if has_injection_issue else 0) - (med_count * 10)),
            "perimeter_data_protection": max(10, 100 - (60 if has_sensitive_issue else 0) - (crit_count * 20)),
        }

        return {
            "score": score,
            "grade": grade,
            "grade_color": grade_color,
            "risk_label": risk_label,
            "crit_count": crit_count,
            "high_count": high_count,
            "med_count": med_count,
            "low_count": low_count,
            "info_count": info_count,
            "total_findings": len(findings),
            "pillars": pillars
        }

    @classmethod
    def evaluate_compliance(cls, findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates compliance across standard international frameworks:
        1. OWASP Top 10 (2021/2026)
        2. ISO/IEC 27001:2022
        3. PCI-DSS v4.0
        4. NIST SP 800-53 Rev 5
        """
        findings = findings or []
        titles_lower = [(f.get("title") or "").lower() + " " + (f.get("owasp_category") or "").lower() for f in findings]
        
        def has_violation(keywords: List[str]) -> bool:
            return any(any(kw in t for kw in keywords) for t in titles_lower)

        # 1. OWASP Top 10 Mapping
        owasp_items = [
            {"id": "A01", "name": "Broken Access Control", "passed": not has_violation(["access control", "unauthorized", "idor", "privilege"]), "impact": "Tinggi"},
            {"id": "A02", "name": "Cryptographic Failures", "passed": not has_violation(["crypto", "tls", "ssl", "cipher", "hsts", "plaintext"]), "impact": "Kritis"},
            {"id": "A03", "name": "Injection (SQLi, XSS, Cmd)", "passed": not has_violation(["injection", "xss", "sqli", "sql injection"]), "impact": "Kritis"},
            {"id": "A04", "name": "Insecure Design", "passed": not has_violation(["insecure design", "business logic", "rate limit"]), "impact": "Sedang"},
            {"id": "A05", "name": "Security Misconfiguration", "passed": not has_violation(["misconfiguration", "header", "cors", "csp", "directory listing"]), "impact": "Tinggi"},
            {"id": "A06", "name": "Vulnerable Components", "passed": not has_violation(["vulnerable component", "outdated", "cve"]), "impact": "Tinggi"},
            {"id": "A07", "name": "Auth & Identification Failures", "passed": not has_violation(["auth", "session", "cookie", "token", "samesite"]), "impact": "Tinggi"},
            {"id": "A08", "name": "Software & Data Integrity", "passed": not has_violation(["integrity", "sri", "pipeline", "signature"]), "impact": "Sedang"},
            {"id": "A09", "name": "Logging & Monitoring", "passed": not has_violation(["logging", "monitoring", "audit trail"]), "impact": "Sedang"},
            {"id": "A10", "name": "Server-Side Request Forgery (SSRF)", "passed": not has_violation(["ssrf", "request forgery"]), "impact": "Kritis"}
        ]
        owasp_pass = sum(1 for i in owasp_items if i["passed"])
        owasp_score = round((owasp_pass / len(owasp_items)) * 100, 1)

        # 2. ISO/IEC 27001:2022 Mapping
        iso_items = [
            {"control": "A.8.20", "name": "Network Security & Boundary Hardening", "passed": not has_violation(["cors", "port", "waf", "open port", "firewall"]), "domain": "Technological Controls"},
            {"control": "A.8.24", "name": "Use of Cryptography & Key Management", "passed": not has_violation(["tls", "ssl", "hsts", "certificate", "cipher"]), "domain": "Information Security"},
            {"control": "A.8.26", "name": "Application Security Requirements", "passed": not has_violation(["injection", "xss", "sqli", "sensitive"]), "domain": "Secure Development"},
            {"control": "A.8.28", "name": "Secure Coding & Input Sanitization", "passed": not has_violation(["xss", "sqli", "injection", "validation"]), "domain": "Development Lifecycle"},
            {"control": "A.8.31", "name": "Separation of Environments & Secrets", "passed": not has_violation([".env", ".git", "secret", "backup", "credential"]), "domain": "Operations Security"},
        ]
        iso_pass = sum(1 for i in iso_items if i["passed"])
        iso_score = round((iso_pass / len(iso_items)) * 100, 1)

        # 3. PCI-DSS v4.0 Mapping
        pci_items = [
            {"req": "Req 4.1", "name": "Strong Cryptography in Transmission", "passed": not has_violation(["tls", "ssl", "hsts", "certificate"]), "standard": "Data in Transit"},
            {"req": "Req 6.4.1", "name": "Protection Against Web Attacks & Injection", "passed": not has_violation(["xss", "sqli", "injection", "csp"]), "standard": "Public Applications"},
            {"req": "Req 6.5.8", "name": "Prevention of Sensitive Data Exposure", "passed": not has_violation([".env", ".git", "secret", "backup.sql"]), "standard": "Sensitive Assets"},
            {"req": "Req 11.3.1", "name": "External Vulnerability Assessments", "passed": len([f for f in findings if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")]) == 0, "standard": "Vulnerability Testing"},
        ]
        pci_pass = sum(1 for i in pci_items if i["passed"])
        pci_score = round((pci_pass / len(pci_items)) * 100, 1)

        # 4. NIST SP 800-53 Rev 5 Mapping
        nist_items = [
            {"control": "SC-8", "name": "Transmission Confidentiality & Integrity", "passed": not has_violation(["tls", "ssl", "hsts"]), "family": "System and Communications Protection"},
            {"control": "SC-13", "name": "Cryptographic Protection", "passed": not has_violation(["cipher", "tls 1.0", "tls 1.1", "certificate"]), "family": "System and Communications Protection"},
            {"control": "SI-10", "name": "Information Input Validation", "passed": not has_violation(["xss", "sqli", "injection"]), "family": "System and Information Integrity"},
            {"control": "AC-3", "name": "Access Enforcement & Permissions", "passed": not has_violation(["access control", "permission", "cors"]), "family": "Access Control"},
        ]
        nist_pass = sum(1 for i in nist_items if i["passed"])
        nist_score = round((nist_pass / len(nist_items)) * 100, 1)

        return {
            "owasp": {
                "name": "OWASP Top 10 (2021 & 2026 Ready)",
                "compliance_score": owasp_score,
                "passed_count": owasp_pass,
                "total_count": len(owasp_items),
                "items": owasp_items,
                "status": "COMPLIANT" if owasp_score >= 90 else "PARTIAL" if owasp_score >= 60 else "NON_COMPLIANT"
            },
            "iso27001": {
                "name": "ISO/IEC 27001:2022 Annex A",
                "compliance_score": iso_score,
                "passed_count": iso_pass,
                "total_count": len(iso_items),
                "items": iso_items,
                "status": "COMPLIANT" if iso_score >= 90 else "PARTIAL" if iso_score >= 60 else "NON_COMPLIANT"
            },
            "pci_dss": {
                "name": "PCI-DSS v4.0 Web Security Standard",
                "compliance_score": pci_score,
                "passed_count": pci_pass,
                "total_count": len(pci_items),
                "items": pci_items,
                "status": "COMPLIANT" if pci_score >= 90 else "PARTIAL" if pci_score >= 60 else "NON_COMPLIANT"
            },
            "nist": {
                "name": "NIST SP 800-53 Rev 5 (FedRAMP Standard)",
                "compliance_score": nist_score,
                "passed_count": nist_pass,
                "total_count": len(nist_items),
                "items": nist_items,
                "status": "COMPLIANT" if nist_score >= 90 else "PARTIAL" if nist_score >= 60 else "NON_COMPLIANT"
            }
        }
