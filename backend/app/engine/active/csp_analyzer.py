"""
CSP (Content Security Policy) Deep Analyzer — 2026 Edition
Parses and audits CSP headers for:
  - Missing directives (default-src, script-src, object-src, base-uri, frame-ancestors)
  - Dangerous values: unsafe-inline, unsafe-eval, data:, blob:, *
  - Known bypass gadgets (JSONP endpoints, Angular, React CDNs with unsafe allowlists)
  - Reflected XSS-enabling misconfigurations
"""
import httpx
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


REQUIRED_DIRECTIVES = [
    "default-src", "script-src", "object-src", "base-uri", "frame-ancestors"
]

DANGEROUS_VALUES = {
    "'unsafe-inline'": {
        "risk": "Allows inline scripts — XSS payloads execute directly if injected into HTML.",
        "severity": "High",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "'unsafe-eval'": {
        "risk": "Allows eval() and Function() — enables DOM-based XSS via JS injection.",
        "severity": "High",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "data:": {
        "risk": "Allows data: URIs — can be used as script source in some browsers.",
        "severity": "Medium",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "blob:": {
        "risk": "Allows blob: URIs — can host dynamic scripts bypassing CSP.",
        "severity": "Medium",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "*": {
        "risk": "Wildcard source — allows scripts/resources from any domain, negates CSP protection.",
        "severity": "Critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    },
    "http:": {
        "risk": "Allows loading resources over insecure HTTP, enabling MitM injection.",
        "severity": "Medium",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    },
}

# Known JSONP/bypass gadget domains that allow CSP bypass
BYPASS_GADGET_DOMAINS = [
    "accounts.google.com",
    "ajax.googleapis.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "code.jquery.com",
    "angular.io",
    "unpkg.com",
    "rawgit.com",
    "rawgithub.com",
    "gstatic.com",
]


def _parse_csp(csp_header: str) -> Dict[str, List[str]]:
    """Parse CSP header string into directive → values dict."""
    directives = {}
    for directive in csp_header.split(";"):
        parts = directive.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        values = [v.lower() for v in parts[1:]]
        directives[name] = values
    return directives


class CSPAnalyzer:
    """
    Deep CSP Policy Analyzer and Bypass Detector.
    """

    async def analyze(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []

        async with httpx.AsyncClient(
            verify=False, timeout=10.0, follow_redirects=True
        ) as client:
            try:
                try:
                    resp = await client.get(
                        target_url,
                        headers={"User-Agent": "VulnHunter/2026"}
                    )
                except (httpx.ConnectError, httpx.RemoteProtocolError):
                    if target_url.startswith("https://"):
                        resp = await client.get("http://" + target_url[8:])
                    else:
                        return findings

                # Check for CSP existence
                csp_raw = (
                    resp.headers.get("content-security-policy")
                    or resp.headers.get("x-content-security-policy")
                    or resp.headers.get("x-webkit-csp")
                )

                if not csp_raw:
                    findings.append({
                        "title": "Missing Content Security Policy (CSP) Header",
                        "severity": "High",
                        "cwe": "CWE-1021",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "description": (
                            "Tidak ada header Content-Security-Policy ditemukan. CSP adalah pertahanan "
                            "utama terhadap serangan Cross-Site Scripting (XSS) dan data injection."
                        ),
                        "remediation": (
                            "Implementasikan CSP dengan direktif minimal: "
                            "Content-Security-Policy: default-src 'self'; script-src 'self'; "
                            "object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
                        ),
                        "evidence": "Header 'Content-Security-Policy' tidak ditemukan pada response.",
                        "target_url": target_url,
                    })
                    return findings

                directives = _parse_csp(csp_raw)

                # Check CSP report-only (weak)
                if resp.headers.get("content-security-policy-report-only"):
                    findings.append({
                        "title": "CSP — Report-Only Mode (Not Enforced)",
                        "severity": "Medium",
                        "cwe": "CWE-1021",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "description": "CSP hanya dalam mode report-only, tidak diterapkan. XSS masih dapat dieksekusi.",
                        "remediation": "Ubah ke 'Content-Security-Policy' (enforcement) setelah menguji policy.",
                        "evidence": "Header 'Content-Security-Policy-Report-Only' ditemukan, bukan enforcement.",
                        "target_url": target_url,
                    })

                # Check missing required directives
                for directive in REQUIRED_DIRECTIVES:
                    if directive not in directives:
                        # If default-src exists, it covers others (partially)
                        if directive != "default-src" and "default-src" in directives:
                            # Only flag as medium if covered by default-src
                            if directive in ("base-uri", "frame-ancestors"):
                                findings.append({
                                    "title": f"CSP — Missing '{directive}' Directive",
                                    "severity": "Medium",
                                    "cwe": "CWE-1021",
                                    "owasp_category": "A05:2021-Security Misconfiguration",
                                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
                                    "description": (
                                        f"Direktif '{directive}' tidak didefinisikan. "
                                        + ("'base-uri' yang hilang memungkinkan injeksi base tag untuk redirect resource URL."
                                           if directive == "base-uri" else
                                           "'frame-ancestors' yang hilang tidak melindungi terhadap Clickjacking.")
                                    ),
                                    "remediation": f"Tambahkan '{directive}' ke CSP policy.",
                                    "evidence": f"Parsed CSP directives: {list(directives.keys())}",
                                    "target_url": target_url,
                                })
                        elif directive == "default-src":
                            findings.append({
                                "title": "CSP — Missing 'default-src' Directive",
                                "severity": "High",
                                "cwe": "CWE-1021",
                                "owasp_category": "A05:2021-Security Misconfiguration",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                                "description": (
                                    "'default-src' tidak ditemukan dalam CSP. Tanpa fallback directive, "
                                    "browser mengizinkan pemuatan resource dari sumber mana pun."
                                ),
                                "remediation": "Tambahkan 'default-src 'self'' sebagai fallback minimal.",
                                "evidence": f"Parsed CSP: {csp_raw[:200]}",
                                "target_url": target_url,
                            })

                # Check dangerous values in each directive
                for dir_name, values in directives.items():
                    for val, info in DANGEROUS_VALUES.items():
                        if val in values:
                            findings.append({
                                "title": f"CSP — Dangerous Value '{val}' in '{dir_name}'",
                                "severity": info["severity"],
                                "cwe": "CWE-1021",
                                "owasp_category": "A05:2021-Security Misconfiguration",
                                "cvss_vector": info["cvss"],
                                "description": (
                                    f"Direktif '{dir_name}' mengandung nilai berbahaya '{val}'. {info['risk']}"
                                ),
                                "remediation": f"Hapus '{val}' dari direktif '{dir_name}' dan gunakan nonce atau hash sebagai gantinya.",
                                "evidence": f"{dir_name}: {' '.join(values)}",
                                "target_url": target_url,
                            })

                # Check bypass gadget domains in script-src
                script_src = directives.get("script-src", directives.get("default-src", []))
                for gadget in BYPASS_GADGET_DOMAINS:
                    for src in script_src:
                        if gadget in src:
                            findings.append({
                                "title": f"CSP — Bypass Gadget Domain Allowed: {gadget}",
                                "severity": "High",
                                "cwe": "CWE-1021",
                                "owasp_category": "A03:2021-Injection",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                                "description": (
                                    f"Domain '{gadget}' diizinkan dalam script-src dan diketahui memiliki "
                                    "endpoint JSONP atau Angular/React template injection yang dapat mem-bypass CSP."
                                ),
                                "remediation": (
                                    f"Hapus '{gadget}' dari script-src. Gunakan hash atau nonce untuk "
                                    "mengizinkan script spesifik."
                                ),
                                "evidence": f"script-src includes: {gadget}",
                                "target_url": target_url,
                            })
                            break

            except (httpx.ConnectError, httpx.TimeoutException):
                pass

        return findings


async def run_csp_terminal(target_url: str) -> str:
    """Generate formatted live CSP audit report for terminal output."""
    lines = [f"[*] Running live CSP Policy Deep Analysis on {target_url}...\n"]
    analyzer = CSPAnalyzer()
    findings = await analyzer.analyze(target_url)

    if not findings:
        lines.append("[+] CSP policy is present and no obvious misconfigurations detected.")
    else:
        lines.append(f"[!] {len(findings)} CSP issue(s) found:\n")
        lines.append("=" * 60)
        for i, f in enumerate(findings, 1):
            sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(f["severity"], "⚪")
            lines.append(f"\n[{i}] {sev_icon} [{f['severity'].upper()}] {f['title']}")
            lines.append(f"    CWE     : {f['cwe']}")
            lines.append(f"    Evidence: {f.get('evidence', 'N/A')[:120]}")
            lines.append(f"    Impact  : {f['description'][:150]}")
            lines.append(f"    Fix     : {f['remediation'][:150]}")

    return "\n".join(lines)
