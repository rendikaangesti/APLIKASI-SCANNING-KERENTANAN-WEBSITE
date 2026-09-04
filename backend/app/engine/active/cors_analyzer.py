"""
CORS Misconfiguration Analyzer — 2026 Edition
Detects: arbitrary origin reflection, null origin, subdomain wildcard, 
credentialed CORS, pre-flight bypass, and cross-origin escalation.
"""
import httpx
import re
from typing import List, Dict, Any
from urllib.parse import urlparse


EVIL_ORIGINS = [
    "https://evil-attacker.com",
    "null",
    "https://attacker.com",
]


def _evil_subdomain(hostname: str) -> str:
    """Generate an attacker subdomain that looks like a subdomain of target."""
    parts = hostname.split(".")
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
        return f"https://evil.{root}"
    return f"https://evil.{hostname}"


class CORSAnalyzer:
    """
    Full CORS Misconfiguration Security Audit Engine.
    Tests for arbitrary origin reflection, null origin, credentialed CORS,
    pre-flight bypass, and subdomain wildcard trust.
    """

    async def analyze(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        probes = EVIL_ORIGINS + [_evil_subdomain(hostname)]

        async with httpx.AsyncClient(
            verify=False, timeout=10.0, follow_redirects=True
        ) as client:
            for origin in probes:
                try:
                    resp = await client.get(
                        target_url,
                        headers={"Origin": origin, "User-Agent": "VulnHunter/2026"},
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    # Case 1: Arbitrary origin reflected
                    if acao == origin and origin != "null":
                        severity = "Critical" if acac == "true" else "High"
                        findings.append({
                            "title": "CORS — Arbitrary Origin Reflection" + (" with Credentials" if acac == "true" else ""),
                            "severity": severity,
                            "cwe": "CWE-942",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" if severity == "Critical"
                                           else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            "description": (
                                f"Server merefleksikan origin '{origin}' secara sembarang pada header "
                                f"'Access-Control-Allow-Origin'. "
                                + (f"Dikombinasikan dengan 'Access-Control-Allow-Credentials: true', "
                                   f"penyerang dapat membaca respons terautentikasi lintas-origin." if acac == "true"
                                   else "Penyerang dapat membaca respons API dari halaman berbahaya.")
                            ),
                            "remediation": (
                                "Validasi origin secara eksplisit menggunakan allowlist. "
                                "Jangan reflect 'Origin' header secara langsung. "
                                "Jika menggunakan kredensial, pastikan origin divalidasi ketat."
                            ),
                            "evidence": f"Request Origin: {origin} → Response ACAO: {acao} | ACAC: {acac or 'absent'}",
                            "target_url": target_url,
                        })

                    # Case 2: Null origin accepted
                    if origin == "null" and acao == "null":
                        findings.append({
                            "title": "CORS — Null Origin Accepted",
                            "severity": "High",
                            "cwe": "CWE-942",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            "description": (
                                "Server menerima request dengan 'Origin: null', yang dapat dieksploitasi "
                                "melalui iframe sandbox atau redirect cross-origin untuk membaca respons sensitif."
                            ),
                            "remediation": "Tolak origin 'null' secara eksplisit pada konfigurasi CORS.",
                            "evidence": f"Request Origin: null → Response ACAO: null | ACAC: {acac or 'absent'}",
                            "target_url": target_url,
                        })

                    # Case 3: Wildcard
                    if acao == "*":
                        findings.append({
                            "title": "CORS — Wildcard Allow-Origin (*)",
                            "severity": "Medium",
                            "cwe": "CWE-942",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "description": (
                                "Server menggunakan wildcard (*) pada 'Access-Control-Allow-Origin', "
                                "mengizinkan semua origin membaca respons. Berisiko jika endpoint mengandung data sensitif."
                            ),
                            "remediation": "Ganti wildcard (*) dengan allowlist origin yang spesifik.",
                            "evidence": f"ACAO: * | ACAC: {acac or 'absent'}",
                            "target_url": target_url,
                        })

                except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout):
                    continue

            # Pre-flight probe
            try:
                preflight = await client.options(
                    target_url,
                    headers={
                        "Origin": "https://evil-attacker.com",
                        "Access-Control-Request-Method": "PUT",
                        "Access-Control-Request-Headers": "x-custom-header",
                    },
                )
                acam = preflight.headers.get("access-control-allow-methods", "")
                acah = preflight.headers.get("access-control-allow-headers", "")
                acao2 = preflight.headers.get("access-control-allow-origin", "")
                if "PUT" in acam.upper() and acao2:
                    findings.append({
                        "title": "CORS — Dangerous Pre-flight Methods Allowed (PUT/DELETE)",
                        "severity": "High",
                        "cwe": "CWE-942",
                        "owasp_category": "A01:2021-Broken Access Control",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
                        "description": (
                            "Pre-flight CORS request mengizinkan metode berbahaya (PUT, DELETE) "
                            "dari origin eksternal, memungkinkan modifikasi data lintas-origin."
                        ),
                        "remediation": "Batasi Access-Control-Allow-Methods hanya pada metode yang benar-benar diperlukan (GET, POST).",
                        "evidence": f"ACAM: {acam} | ACAH: {acah} | ACAO: {acao2}",
                        "target_url": target_url,
                    })
            except Exception:
                pass

        return findings


async def run_cors_terminal(target_url: str) -> str:
    """Generate formatted live CORS audit report for terminal output."""
    lines = [f"[*] Running live CORS Misconfiguration Audit on {target_url}...\n"]
    analyzer = CORSAnalyzer()
    findings = await analyzer.analyze(target_url)

    if not findings:
        lines.append("[+] No CORS misconfigurations detected. Policy appears correctly scoped.")
    else:
        lines.append(f"[!] {len(findings)} CORS issue(s) found:\n")
        lines.append("=" * 60)
        for i, f in enumerate(findings, 1):
            sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(f["severity"], "⚪")
            lines.append(f"\n[{i}] {sev_icon} [{f['severity'].upper()}] {f['title']}")
            lines.append(f"    CWE     : {f['cwe']} | OWASP: {f['owasp_category']}")
            lines.append(f"    Evidence: {f['evidence']}")
            lines.append(f"    Impact  : {f['description']}")
            lines.append(f"    Fix     : {f['remediation']}")

    return "\n".join(lines)
