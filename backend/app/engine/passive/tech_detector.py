import httpx
import re
from typing import List, Dict, Any

class TechnologyDetector:
    """
    Fingerprinting teknologi dan Information Disclosure pada response web.
    """

    TECH_SIGNATURES = [
        {"name": "WordPress", "regex": r"wp-content|wp-includes|xmlrpc\.php", "owasp": "A05:2021-Security Misconfiguration"},
        {"name": "Laravel", "header": "set-cookie", "regex": r"laravel_session|XSRF-TOKEN", "owasp": "A05:2021-Security Misconfiguration"},
        {"name": "Django", "header": "set-cookie", "regex": r"csrftoken|django", "owasp": "A05:2021-Security Misconfiguration"},
        {"name": "Express.js", "header": "x-powered-by", "regex": r"Express", "owasp": "A05:2021-Security Misconfiguration"},
        {"name": "PHP", "header": "x-powered-by", "regex": r"PHP/[\d\.]+", "owasp": "A05:2021-Security Misconfiguration"},
        {"name": "ASP.NET", "header": "x-powered-by", "regex": r"ASP\.NET", "owasp": "A05:2021-Security Misconfiguration"},
    ]

    async def analyze(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            try:
                response = await client.get(target_url)
                headers = response.headers
                body = response.text

                # Check X-Powered-By Disclosure
                if "x-powered-by" in headers:
                    val = headers["x-powered-by"]
                    findings.append({
                        "title": f"Technology Disclosure via 'X-Powered-By' ({val})",
                        "severity": "Low",
                        "cwe": "CWE-200",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "description": f"Server secara eksplisit mempublikasikan stack backend melalui header X-Powered-By: {val}.",
                        "remediation": "Hapus header 'X-Powered-By' pada konfigurasi backend/web framework.",
                        "evidence": f"X-Powered-By: {val}",
                        "target_url": target_url
                    })

                # Check Server Header
                if "server" in headers:
                    server_val = headers["server"]
                    findings.append({
                        "title": f"Server Banner Exposure: {server_val}",
                        "severity": "Info",
                        "cwe": "CWE-200",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        "description": f"Web server mengekspos identifier: '{server_val}'.",
                        "remediation": "Sembunyikan atau samarkan versi web server untuk mencegah serangan terarah berbasis versi CVE.",
                        "evidence": f"Server: {server_val}",
                        "target_url": target_url
                    })

                # Check signatures
                for sig in self.TECH_SIGNATURES:
                    if "header" in sig and sig["header"] in headers:
                        if re.search(sig["regex"], headers[sig["header"]], re.IGNORECASE):
                            findings.append({
                                "title": f"Detected Web Stack: {sig['name']}",
                                "severity": "Info",
                                "cwe": "CWE-200",
                                "owasp_category": sig["owasp"],
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                                "description": f"Stack teknologi '{sig['name']}' teridentifikasi dari response headers.",
                                "remediation": "Pastikan framework dan seluruh dependensi diperbarui ke versi rilis keamanan terbaru.",
                                "evidence": f"Header {sig['header']}: {headers[sig['header']]}",
                                "target_url": target_url
                            })
            except Exception:
                pass

        return findings
