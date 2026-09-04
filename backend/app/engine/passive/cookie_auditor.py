import httpx
from typing import List, Dict, Any

class CookieSecurityAuditor:
    """
    Memeriksa keamanan atribut Cookie (HttpOnly, Secure, SameSite) sesuai standar OWASP.
    """

    async def analyze(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            try:
                response = await client.get(target_url)
                set_cookie_headers = response.headers.get_list("set-cookie")

                for cookie_str in set_cookie_headers:
                    parts = [p.strip() for p in cookie_str.split(";")]
                    cookie_name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
                    lower_parts = [p.lower() for p in parts]

                    has_httponly = any("httponly" in p for p in lower_parts)
                    has_secure = any("secure" in p for p in lower_parts)
                    has_samesite = any("samesite" in p for p in lower_parts)

                    if not has_httponly:
                        findings.append({
                            "title": f"Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                            "severity": "Medium",
                            "cwe": "CWE-1004",
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", # 6.5 Medium
                            "description": f"Cookie '{cookie_name}' dapat diakses via JavaScript (`document.cookie`), meningkatkan risiko pencurian sesi saat terjadi serangan XSS.",
                            "remediation": f"Tambahkan flag `HttpOnly` pada cookie {cookie_name} saat inisialisasi session.",
                            "evidence": f"Set-Cookie: {cookie_str}",
                            "target_url": target_url
                        })

                    if not has_secure:
                        findings.append({
                            "title": f"Cookie Missing 'Secure' Flag ({cookie_name})",
                            "severity": "Medium",
                            "cwe": "CWE-614",
                            "owasp_category": "A02:2021-Cryptographic Failures",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                            "description": f"Cookie '{cookie_name}' dapat dikirim melalui sambungan HTTP tanpa enkripsi, rentan disadap.",
                            "remediation": f"Tambahkan flag `Secure` pada cookie {cookie_name} agar hanya dikirim via protokol HTTPS.",
                            "evidence": f"Set-Cookie: {cookie_str}",
                            "target_url": target_url
                        })

                    if not has_samesite:
                        findings.append({
                            "title": f"Cookie Missing 'SameSite' Attribute ({cookie_name})",
                            "severity": "Low",
                            "cwe": "CWE-1275",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                            "description": f"Cookie '{cookie_name}' tidak mendefinisikan SameSite attribute, rentan terhadap serangan Cross-Site Request Forgery (CSRF).",
                            "remediation": f"Konfigurasikan `SameSite=Lax` atau `SameSite=Strict` pada cookie {cookie_name}.",
                            "evidence": f"Set-Cookie: {cookie_str}",
                            "target_url": target_url
                        })
            except Exception:
                pass

        return findings
