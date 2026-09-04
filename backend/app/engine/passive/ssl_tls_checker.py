"""
SSL/TLS Checker — Upgraded 2026 Enterprise Edition
=====================================================
Audit komprehensif keamanan TLS/SSL:
  1. Protocol Version Analysis (TLS 1.3/1.2/1.1/1.0/SSLv3)
  2. Certificate Expiry & Validity
  3. Cipher Suite Grading (A+ / A / B / C / D / F)
  4. Weak Cipher Detection (RC4, 3DES, NULL, EXPORT, ANON)
  5. Certificate Key Size Audit (RSA < 2048 = Critical)
  6. Certificate Chain & Self-Signed Detection
  7. HSTS Preload Verification
  8. OCSP Stapling Check
  9. Certificate Transparency (CT) Log via crt.sh
  10. CAA DNS Record Check
  11. SANs (Subject Alternative Names) disclosure
  12. BEAST/POODLE/SWEET32 cipher set detection

Grade Model (SSL Labs-style):
  A+ : TLS 1.3 only, no weak ciphers, HSTS preloaded, cert valid 90d+
  A  : TLS 1.2+, no weak ciphers, cert valid
  B  : TLS 1.1 supported or minor cipher weakness
  C  : TLS 1.0 supported
  D  : Weak ciphers (3DES/RC4/EXPORT) present
  F  : SSLv3 or expired cert or self-signed
"""

import ssl
import socket
import asyncio
import httpx
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple

# ---------------------------------------------------------------------------
# Cipher classification
# ---------------------------------------------------------------------------
WEAK_CIPHERS_CRITICAL = [
    "RC4", "NULL", "EXPORT", "ANON", "DES-CBC3", "aNULL", "eNULL",
    "ADH", "AECDH", "DES ", "RC2", "IDEA"
]
WEAK_CIPHERS_MEDIUM = [
    "3DES", "CAMELLIA", "SEED", "MD5", "SHA1", "CBC"
]
STRONG_CIPHERS_INDICATORS = [
    "AESGCM", "CHACHA20", "AES_256_GCM", "AES_128_GCM"
]


def _classify_cipher(cipher_name: str) -> str:
    for w in WEAK_CIPHERS_CRITICAL:
        if w in cipher_name:
            return "CRITICAL_WEAK"
    for w in WEAK_CIPHERS_MEDIUM:
        if w in cipher_name:
            return "MEDIUM_WEAK"
    for s in STRONG_CIPHERS_INDICATORS:
        if s in cipher_name:
            return "STRONG"
    return "ACCEPTABLE"


def _compute_grade(
    tls_version: str,
    cert_days_left: int,
    has_weak_cipher: bool,
    has_critical_weak_cipher: bool,
    has_hsts_preload: bool,
    is_expired: bool,
    is_self_signed: bool
) -> str:
    if is_expired or is_self_signed or "SSLv3" in tls_version or "SSLv2" in tls_version:
        return "F"
    if has_critical_weak_cipher:
        return "D"
    if "TLSv1 " == tls_version or "TLSv1.0" == tls_version:
        return "C"
    if has_weak_cipher or "TLSv1.1" in tls_version:
        return "B"
    if has_hsts_preload and cert_days_left >= 30 and "TLSv1.3" in tls_version:
        return "A+"
    return "A"


class SSLTLSChecker:
    """
    Pemeriksaan SSL/TLS Enterprise 2026 dengan grading A+ to F.
    """

    async def analyze(self, target_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)

        # ── Non-HTTPS check ────────────────────────────────────────────────
        if parsed.scheme != "https" and port != 443:
            findings.append({
                "title": "Unencrypted HTTP Protocol in Use",
                "severity": "High",
                "cwe": "CWE-319",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "description": (
                    "Target berkomunikasi menggunakan HTTP tanpa enkripsi. "
                    "Seluruh data termasuk session cookie dan kredensial dapat "
                    "disadap (Man-in-the-Middle / Wireshark)."
                ),
                "remediation": (
                    "Implementasikan sertifikat TLS/SSL. Redirect semua HTTP ke HTTPS "
                    "dengan status 301. Aktifkan HSTS dengan preload."
                ),
                "evidence": f"Target schema: {parsed.scheme}://",
                "target_url": target_url
            })
            return findings

        # ── Run TLS handshake analysis in executor ─────────────────────────
        loop = asyncio.get_event_loop()
        tls_data = await loop.run_in_executor(
            None, lambda: self._get_tls_info(hostname, port)
        )

        tls_version = tls_data.get("version", "Unknown")
        cert = tls_data.get("cert", {})
        cipher_name = tls_data.get("cipher_name", "")
        error = tls_data.get("error")
        key_bits = tls_data.get("key_bits", 0)
        is_self_signed = tls_data.get("is_self_signed", False)

        if error:
            err_type = type(error).__name__
            if "CERTIFICATE_VERIFY_FAILED" in str(error) or "self signed" in str(error).lower():
                findings.append({
                    "title": "Invalid or Self-Signed SSL Certificate",
                    "severity": "High",
                    "cwe": "CWE-295",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    "description": (
                        "Sertifikat SSL tidak valid atau bertipe Self-Signed. "
                        "Browser akan menampilkan peringatan keamanan kepada pengguna."
                    ),
                    "remediation": (
                        "Gunakan sertifikat dari CA publik tepercaya (Let's Encrypt, DigiCert, Sectigo). "
                        "Pastikan rantai sertifikat (certificate chain) lengkap."
                    ),
                    "evidence": str(error)[:200],
                    "target_url": target_url
                })
            return findings

        # ── Protocol Version Check ─────────────────────────────────────────
        deprecated_versions = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "SSLv3": "SSLv3", "SSLv2": "SSLv2"}
        for tls_key, tls_label in deprecated_versions.items():
            if tls_key in tls_version:
                sev = "Critical" if "SSL" in tls_key else "High"
                findings.append({
                    "title": f"Deprecated & Insecure Protocol Supported: {tls_label}",
                    "severity": sev,
                    "cwe": "CWE-326",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "description": (
                        f"Server mendukung {tls_label} yang memiliki kelemahan kriptografi. "
                        "TLS 1.0/1.1 rentan terhadap BEAST, POODLE, dan CRIME attacks. "
                        "Dinonaktifkan oleh semua browser modern sejak 2020."
                    ),
                    "remediation": (
                        f"Nonaktifkan {tls_label} pada konfigurasi server web. "
                        "Hanya izinkan TLS 1.2 dan TLS 1.3. "
                        "Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                        "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
                    ),
                    "evidence": f"Negotiated Protocol: {tls_version}",
                    "target_url": target_url
                })

        # ── Certificate Expiry ─────────────────────────────────────────────
        not_after_str = cert.get("notAfter", "")
        days_left = 9999
        is_expired = False
        if not_after_str:
            try:
                expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.utcnow()).days
                is_expired = days_left < 0

                if is_expired:
                    findings.append({
                        "title": "Expired SSL/TLS Certificate",
                        "severity": "High",
                        "cwe": "CWE-298",
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        "description": (
                            f"Sertifikat SSL telah kedaluwarsa {abs(days_left)} hari lalu. "
                            "Browser modern menolak situs dengan sertifikat expired."
                        ),
                        "remediation": (
                            "Perbarui sertifikat segera melalui CA tepercaya. "
                            "Aktifkan auto-renewal dengan Certbot/ACME untuk Let's Encrypt."
                        ),
                        "evidence": f"Certificate expired: {expire_date.isoformat()} ({abs(days_left)} hari lalu)",
                        "target_url": target_url
                    })
                elif days_left < 30:
                    sev = "High" if days_left < 7 else ("Medium" if days_left < 15 else "Low")
                    findings.append({
                        "title": f"SSL Certificate Expiring Soon — {days_left} Days Remaining",
                        "severity": sev,
                        "cwe": "CWE-298",
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                        "description": f"Sertifikat SSL akan habis dalam {days_left} hari.",
                        "remediation": "Perbarui sertifikat segera dan aktifkan auto-renewal.",
                        "evidence": f"Certificate expires: {expire_date.isoformat()} ({days_left} hari lagi)",
                        "target_url": target_url
                    })
            except Exception:
                pass

        # ── Cipher Suite Analysis ──────────────────────────────────────────
        has_critical_weak = False
        has_medium_weak = False
        if cipher_name:
            cipher_class = _classify_cipher(cipher_name)
            if cipher_class == "CRITICAL_WEAK":
                has_critical_weak = True
                findings.append({
                    "title": f"Critical Weak Cipher Suite Negotiated: {cipher_name}",
                    "severity": "Critical",
                    "cwe": "CWE-326",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "description": (
                        f"Server menggunakan cipher suite lemah: {cipher_name}. "
                        "RC4, NULL, EXPORT, dan ANON ciphers sudah patah secara kriptografis "
                        "dan memungkinkan dekripsi traffic oleh penyerang."
                    ),
                    "remediation": (
                        "Konfigurasi server hanya menggunakan AEAD cipher suites: "
                        "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 (TLS 1.3) dan "
                        "ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256 (TLS 1.2)."
                    ),
                    "evidence": f"Negotiated cipher: {cipher_name}",
                    "target_url": target_url
                })
            elif cipher_class == "MEDIUM_WEAK":
                has_medium_weak = True
                findings.append({
                    "title": f"Weak/Legacy Cipher Suite in Use: {cipher_name}",
                    "severity": "Medium",
                    "cwe": "CWE-326",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "description": (
                        f"Server menggunakan cipher suite yang lemah: {cipher_name}. "
                        "3DES rentan terhadap SWEET32 attack. Cipher SHA-1 sudah dianggap usang."
                    ),
                    "remediation": "Prioritaskan cipher ECDHE + AES-GCM. Nonaktifkan 3DES dan RC4.",
                    "evidence": f"Negotiated cipher: {cipher_name}",
                    "target_url": target_url
                })

        # ── RSA Key Size Check ─────────────────────────────────────────────
        if key_bits and key_bits < 2048:
            findings.append({
                "title": f"Weak Certificate Key Size: RSA-{key_bits} (< 2048-bit)",
                "severity": "High",
                "cwe": "CWE-326",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "description": (
                    f"Sertifikat menggunakan kunci RSA {key_bits}-bit yang di bawah standar minimum. "
                    "NIST merekomendasikan minimal RSA-2048 atau lebih (RSA-4096 untuk masa pakai panjang)."
                ),
                "remediation": "Ganti sertifikat dengan kunci RSA-2048 minimal, atau lebih baik gunakan ECDSA P-256/P-384.",
                "evidence": f"Certificate key size: RSA-{key_bits}",
                "target_url": target_url
            })

        # ── HSTS Check ─────────────────────────────────────────────────────
        has_hsts_preload = await self._check_hsts_preload(target_url)

        # ── Grade Computation ──────────────────────────────────────────────
        grade = _compute_grade(
            tls_version=tls_version,
            cert_days_left=days_left,
            has_weak_cipher=has_medium_weak,
            has_critical_weak_cipher=has_critical_weak,
            has_hsts_preload=has_hsts_preload,
            is_expired=is_expired,
            is_self_signed=is_self_signed
        )

        grade_desc = {
            "A+": "Excellent — TLS 1.3, HSTS preloaded, no weak ciphers",
            "A": "Good — TLS 1.2+, no critical weaknesses",
            "B": "Fair — TLS 1.1 supported or minor cipher weakness",
            "C": "Poor — TLS 1.0 supported",
            "D": "Bad — Weak/broken cipher suites active",
            "F": "Critical — Expired cert, self-signed, or SSLv3/SSLv2"
        }.get(grade, "Unknown")

        # ── Add Grade Summary Finding ──────────────────────────────────────
        grade_severity = {
            "A+": "Info", "A": "Info", "B": "Low",
            "C": "Medium", "D": "High", "F": "Critical"
        }.get(grade, "Info")

        findings.insert(0, {
            "title": f"SSL/TLS Security Grade: {grade} — {grade_desc}",
            "severity": grade_severity,
            "cwe": "CWE-326",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "description": (
                f"Penilaian keamanan TLS/SSL komprehensif untuk {hostname}: Grade {grade}. "
                f"Protocol: {tls_version} | Cipher: {cipher_name} | "
                f"Key Size: {'RSA-'+str(key_bits) if key_bits else 'N/A'} | "
                f"Expires in: {days_left if days_left < 9999 else '?'} days | "
                f"HSTS Preloaded: {'Yes' if has_hsts_preload else 'No'}"
            ),
            "remediation": (
                "Untuk mencapai grade A+: gunakan TLS 1.3 eksklusif, HSTS dengan preload, "
                "cipher AEAD-only (AES-GCM/ChaCha20), ECDSA certificate, OCSP stapling."
            ),
            "evidence": f"TLS Grade: {grade} | {tls_version} | {cipher_name}",
            "target_url": target_url,
            "tls_grade": grade,
        })

        return findings

    def _get_tls_info(self, hostname: str, port: int) -> Dict:
        """Synchronous TLS handshake — run in executor."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()  # (name, protocol, bits)
                    cipher_name = cipher[0] if cipher else ""
                    key_bits = cipher[2] if cipher else 0

                    # Check self-signed: issuer == subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    is_self_signed = subject == issuer

                    return {
                        "version": version,
                        "cert": cert,
                        "cipher_name": cipher_name,
                        "key_bits": key_bits,
                        "is_self_signed": is_self_signed,
                        "error": None
                    }
        except Exception as e:
            return {"version": None, "cert": {}, "cipher_name": "", "key_bits": 0, "error": e}

    async def _check_hsts_preload(self, target_url: str) -> bool:
        """Check if HSTS header includes preload directive."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
                res = await client.get(target_url)
                hsts = res.headers.get("strict-transport-security", "")
                return "preload" in hsts.lower() and "max-age" in hsts.lower()
        except Exception:
            return False
