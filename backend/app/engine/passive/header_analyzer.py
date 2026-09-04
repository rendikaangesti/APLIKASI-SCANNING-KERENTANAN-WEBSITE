import httpx
from typing import List, Dict, Any

class SecurityHeaderAnalyzer:
    """
    Menganalisis implementasi HTTP Security Headers berdasarkan standar OWASP 2026 & CIS Benchmark.
    """
    
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "required": True,
            "min_max_age": 31536000,
            "cwe": "CWE-319",
            "owasp": "A02:2021-Cryptographic Failures",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", # 5.4 Medium
            "remediation": "Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "desc": "Target tidak menerapkan header HSTS (atau tanpa preload/subdomains), memungkinkan risiko Man-in-the-Middle (MitM) melalui downgrade HTTP."
        },
        "Content-Security-Policy": {
            "required": True,
            "cwe": "CWE-1021",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", # 6.1 Medium
            "remediation": "Konfigurasikan CSP yang ketat untuk membatasi sumber script, gambar, style, dan frame. Hindari 'unsafe-inline' dan 'unsafe-eval'.",
            "desc": "Header Content-Security-Policy (CSP) tidak ada atau terlalu permisif, mengurangi perlindungan terhadap Cross-Site Scripting (XSS) dan data injection."
        },
        "X-Frame-Options": {
            "required": True,
            "allowed_values": ["DENY", "SAMEORIGIN"],
            "cwe": "CWE-1021",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", # 4.3 Medium
            "remediation": "Tambahkan header: X-Frame-Options: DENY atau SAMEORIGIN pada seluruh response halaman HTML.",
            "desc": "Target rentan terhadap serangan Clickjacking karena tidak membatasi rendering frame/iframe oleh situs lain."
        },
        "X-Content-Type-Options": {
            "required": True,
            "expected": "nosniff",
            "cwe": "CWE-16",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", # 3.1 Low
            "remediation": "Tambahkan header: X-Content-Type-Options: nosniff",
            "desc": "Browser dapat melakukan MIME-type sniffing terhadap response file, berpotensi mengeksekusi file non-executable sebagai script."
        },
        "Referrer-Policy": {
            "required": True,
            "cwe": "CWE-116",
            "owasp": "A01:2021-Broken Access Control",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", # 3.1 Low
            "remediation": "Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin atau no-referrer",
            "desc": "Informasi URL sensitif (seperti parameter token/ID) dapat bocor ke server pihak ketiga melalui header Referer."
        },
        "Permissions-Policy": {
            "required": True,
            "cwe": "CWE-16",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", # 3.1 Low
            "remediation": "Tambahkan header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
            "desc": "Akses API sensitif browser (kamera, mikrofon, geolocation, payment) tidak dibatasi secara eksplisit melalui Permissions-Policy."
        },
        "Cross-Origin-Opener-Policy": {
            "required": False,
            "cwe": "CWE-16",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", # 3.1 Low
            "remediation": "Tambahkan header: Cross-Origin-Opener-Policy: same-origin untuk mengisolasi browsing context dari tab eksternal.",
            "desc": "Ketiadaan COOP memungkinkan potensi serangan Spectre-style side-channel dan manipulasi window.opener oleh situs eksternal."
        },
        "Cross-Origin-Resource-Policy": {
            "required": False,
            "cwe": "CWE-16",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", # 3.1 Low
            "remediation": "Tambahkan header: Cross-Origin-Resource-Policy: same-origin atau same-site",
            "desc": "Header CORP tidak dideklarasikan, memungkinkan aset privat di-load lintas domain (Hotlinking / Cross-Origin Leaks)."
        }
    }

    async def analyze(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            try:
                try:
                    response = await client.get(target_url)
                except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError):
                    if target_url.startswith("https://"):
                        response = await client.get("http://" + target_url[8:])
                    else:
                        raise
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # Check for missing standard security headers
                for header_name, rule in self.SECURITY_HEADERS.items():
                    header_lower = header_name.lower()
                    if header_lower not in headers:
                        sev = "Medium" if ("Security" in header_name or "Frame" in header_name) else ("Low" if rule["required"] else "Info")
                        findings.append({
                            "title": f"Missing Security Header: {header_name}",
                            "severity": sev,
                            "cwe": rule["cwe"],
                            "owasp_category": rule["owasp"],
                            "cvss_vector": rule["cvss_vector"],
                            "description": rule["desc"],
                            "remediation": rule["remediation"],
                            "evidence": f"HTTP response dari {target_url} tidak menyertakan header '{header_name}'",
                            "target_url": target_url,
                        })
                    else:
                        val = headers[header_lower]
                        # Check CORS misconfigurations
                        if header_lower == "access-control-allow-origin" and val == "*":
                            findings.append({
                                "title": "Insecure CORS Wildcard Header (Access-Control-Allow-Origin: *)",
                                "severity": "Medium",
                                "cwe": "CWE-942",
                                "owasp_category": "A01:2021-Broken Access Control",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                                "description": "Server mengizinkan akses Cross-Origin dari semua domain sembarang (*), berpotensi mengekspos data internal ke pihak ketiga.",
                                "remediation": "Batasi header Access-Control-Allow-Origin hanya ke domain tepercaya (whitelisted domains).",
                                "evidence": f"Access-Control-Allow-Origin: {val}",
                                "target_url": target_url
                            })

                # Check Server Banner Information Leakage
                server_val = headers.get("server") or headers.get("x-powered-by")
                if server_val:
                    findings.append({
                        "title": f"Server Banner & Technology Leakage ({server_val})",
                        "severity": "Info",
                        "cwe": "CWE-200",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "description": f"Server web membocorkan informasi versi teknologi perangkat lunak melalui header: '{server_val}'.",
                        "remediation": "Sembunyikan header 'Server' (server_tokens off pada Nginx) dan hapus header 'X-Powered-By' pada konfigurasi aplikasi.",
                        "evidence": f"Header Server/X-Powered-By ditemukan: {server_val}",
                        "target_url": target_url,
                    })

                return findings

            except Exception as e:
                findings.append({
                    "title": "Target Connection Warning during Header Analysis",
                    "severity": "Info",
                    "cwe": "CWE-200",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "description": f"Tidak dapat terhubung secara penuh ke target untuk membaca header: {str(e)}",
                    "remediation": "Pastikan web server target aktif dan dapat menerima koneksi HTTP/HTTPS.",
                    "evidence": str(e),
                    "target_url": target_url
                })
                return findings
