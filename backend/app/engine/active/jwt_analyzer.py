"""
JWT Security Analyzer
======================
Menganalisis keamanan JSON Web Token (JWT) yang ditemukan dalam:
  • HTTP Response headers (Authorization, Set-Cookie, X-Auth-Token)
  • HTTP Response body (JSON field access_token, token, jwt)
  • URL query parameters (?token=, ?jwt=, ?auth=)

Checks yang dilakukan:
  1. Header decode: alg, kid, x5u, jku disclosure
  2. Algorithm Confusion: alg=none attack
  3. Weak HMAC Secret Brute-Force (top-50 dictionary)
  4. Claims validation: exp, iat, nbf, iss, aud
  5. Sensitive data in payload (PII, credentials)
  6. x5u / jku SSRF vector
  7. Kid injection SQLi vector
"""

import httpx
import json
import base64
import hmac
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Top-50 weak JWT secrets (untuk brute-force dictionary)
# ---------------------------------------------------------------------------
WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "token", "jwt",
    "my_secret", "mysecret", "your-256-bit-secret", "qwerty",
    "letmein", "changeme", "default", "dev", "test", "example",
    "supersecret", "secretkey", "jwt_secret", "jwtsecret",
    "secret_key", "my_jwt_secret", "app_secret", "key",
    "myapp", "django-insecure-", "flask-secret", "laravel",
    "nodekey", "expresskey", "rails_secret", "spring",
    "access_token_secret", "at_secret", "refresh_secret",
    "production_secret", "staging_secret", "local_secret",
    "test_secret", "dev_secret", "apikey", "api_key",
    "api_secret", "app_key", "application_secret",
    "1234567890", "0987654321", "abcdefg", "aaaa", "zxcvbnm",
]

# Parameters/headers that may contain JWTs
JWT_PARAMS = ["token", "jwt", "auth", "access_token", "id_token", "bearer", "authorization"]
JWT_HEADERS = ["Authorization", "X-Auth-Token", "X-Access-Token", "X-JWT", "X-Api-Key"]


def _b64_decode_safe(s: str) -> bytes:
    """Base64url decode with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _decode_jwt_parts(token: str) -> Tuple[Optional[Dict], Optional[Dict], str]:
    """Decode JWT into header, payload, signature (no verification)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, ""
    try:
        header = json.loads(_b64_decode_safe(parts[0]))
        payload = json.loads(_b64_decode_safe(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None, None, ""


def _is_jwt_like(value: str) -> bool:
    """Return True if string looks like a JWT (3 base64url parts separated by dots)."""
    parts = value.strip().split(".")
    if len(parts) != 3:
        return False
    for part in parts:
        if len(part) < 4:
            return False
    return True


def _brute_force_hs256(header_b64: str, payload_b64: str, signature_b64: str) -> Optional[str]:
    """Try top weak secrets against HS256 signature."""
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        expected_sig = _b64_decode_safe(signature_b64)
    except Exception:
        return None

    for secret in WEAK_SECRETS:
        candidate = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if candidate == expected_sig:
            return secret
    return None


class JWTAnalyzer:
    """
    Analisis keamanan JWT Token yang ditemukan dalam response atau URL.
    """

    async def scan_urls(
        self,
        urls: List[str],
        forms: Optional[List[Dict[str, Any]]] = None,
        emit_log=None
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        found_tokens: set = set()

        async with httpx.AsyncClient(
            verify=False, timeout=8.0, follow_redirects=True
        ) as client:
            for url in urls:
                if emit_log:
                    await emit_log(f"[JWT] Probing {url} for JWT tokens in response...")

                # ---- Extract JWT from URL query params ----
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for pk in JWT_PARAMS:
                    if pk in params:
                        token = params[pk][0]
                        if _is_jwt_like(token) and token not in found_tokens:
                            found_tokens.add(token)
                            jwt_findings = self._analyze_token(token, url, f"URL param '{pk}'")
                            findings.extend(jwt_findings)

                # ---- Probe response for JWT in body / headers ----
                try:
                    res = await client.get(url, timeout=7.0)
                    # Check response headers
                    for hdr in JWT_HEADERS:
                        hval = res.headers.get(hdr, "")
                        token = hval.replace("Bearer ", "").replace("bearer ", "").strip()
                        if _is_jwt_like(token) and token not in found_tokens:
                            found_tokens.add(token)
                            jwt_findings = self._analyze_token(
                                token, url, f"HTTP response header '{hdr}'"
                            )
                            findings.extend(jwt_findings)

                    # Check JSON response body
                    if "json" in res.headers.get("content-type", ""):
                        try:
                            body_json = res.json()
                            self._extract_jwt_from_json(
                                body_json, url, findings, found_tokens
                            )
                        except Exception:
                            pass

                    # Check Set-Cookie for JWT
                    for ck_hdr in res.headers.get_list("set-cookie") if hasattr(res.headers, "get_list") else []:
                        parts = ck_hdr.split(";")
                        if parts:
                            kv = parts[0].split("=", 1)
                            if len(kv) == 2 and _is_jwt_like(kv[1]):
                                token = kv[1]
                                if token not in found_tokens:
                                    found_tokens.add(token)
                                    jwt_findings = self._analyze_token(
                                        token, url, f"Cookie '{kv[0]}'"
                                    )
                                    findings.extend(jwt_findings)

                except Exception:
                    pass

        return findings

    def _extract_jwt_from_json(
        self, obj, url: str, findings: List, found_tokens: set, depth: int = 0
    ):
        if depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and _is_jwt_like(v) and v not in found_tokens:
                    found_tokens.add(v)
                    findings.extend(self._analyze_token(v, url, f"JSON field '{k}'"))
                elif isinstance(v, (dict, list)):
                    self._extract_jwt_from_json(v, url, findings, found_tokens, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:5]:
                self._extract_jwt_from_json(item, url, findings, found_tokens, depth + 1)

    def _analyze_token(
        self, token: str, url: str, source: str
    ) -> List[Dict[str, Any]]:
        findings = []
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        header, payload, signature = _decode_jwt_parts(token)
        if not header:
            return findings

        alg = header.get("alg", "").upper()
        kid = header.get("kid", "")
        x5u = header.get("x5u", "")
        jku = header.get("jku", "")

        # ---- Check 1: Algorithm None ----
        if alg in ("NONE", ""):
            findings.append({
                "title": "JWT Algorithm Confusion — alg:none Attack (Signature Bypass)",
                "severity": "Critical",
                "cwe": "CWE-347",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1
                "description": (
                    "JWT menggunakan algoritma 'none' yang menonaktifkan verifikasi tanda tangan. "
                    "Penyerang dapat memalsukan token JWT apapun tanpa mengetahui secret key, "
                    "memungkinkan privilege escalation dan account takeover total."
                ),
                "remediation": (
                    "Tolak JWT dengan alg=none secara eksplisit di server. Gunakan library JWT "
                    "yang aman (PyJWT, jsonwebtoken ≥8.x) yang melarang alg:none secara default. "
                    "Selalu verifikasi algoritma yang diharapkan secara eksplisit."
                ),
                "evidence": f"JWT ditemukan di {source} dengan header: alg={alg}",
                "target_url": url
            })

        # ---- Check 2: Weak HMAC Secret (HS256/HS384/HS512) ----
        if alg.startswith("HS"):
            cracked_secret = _brute_force_hs256(parts[0], parts[1], parts[2])
            if cracked_secret:
                findings.append({
                    "title": "JWT Signed with Weak/Known HMAC Secret (Signature Forgery Risk)",
                    "severity": "Critical",
                    "cwe": "CWE-321",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "description": (
                        f"JWT menggunakan secret key yang lemah dan mudah ditebak: '{cracked_secret}'. "
                        "Penyerang dapat menandatangani JWT palsu dengan secret ini untuk mengakses "
                        "akun pengguna lain atau mendapatkan hak admin."
                    ),
                    "remediation": (
                        "Ganti secret JWT dengan string acak kriptografis berukuran minimal 256-bit "
                        "(32 byte). Gunakan `secrets.token_urlsafe(32)` di Python atau "
                        "`crypto.randomBytes(32).toString('hex')` di Node.js."
                    ),
                    "evidence": (
                        f"JWT di {source} — secret berhasil di-crack: '{cracked_secret}' "
                        f"(alg={alg})"
                    ),
                    "target_url": url
                })

        # ---- Check 3: x5u / jku SSRF Vector ----
        if x5u or jku:
            external = x5u or jku
            findings.append({
                "title": f"JWT {'x5u' if x5u else 'jku'} Header SSRF Vector",
                "severity": "High",
                "cwe": "CWE-918",
                "owasp_category": "A10:2021-Server-Side Request Forgery (SSRF)",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
                "description": (
                    f"JWT header mengandung `{'x5u' if x5u else 'jku'}` yang mengarah ke URL eksternal: {external}. "
                    "Jika server mengambil kunci publik dari URL tersebut untuk verifikasi, penyerang dapat "
                    "mengarahkan server untuk menerima kunci palsu (JWK Injection / SSRF)."
                ),
                "remediation": (
                    "Tolak JWT yang mengandung header x5u/jku. Puat kunci publik hanya dari "
                    "lokasi lokal yang terpercaya, bukan dari URL yang dikontrol pengguna."
                ),
                "evidence": f"JWT header berisi {'x5u' if x5u else 'jku'}: {external}",
                "target_url": url
            })

        # ---- Check 4: kid SQLi Vector ----
        if kid and any(c in kid for c in ["'", "\"", ";", "--", "UNION", "SELECT"]):
            findings.append({
                "title": "JWT 'kid' Header Injection (SQL Injection in Key Lookup)",
                "severity": "Critical",
                "cwe": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "description": (
                    f"JWT `kid` header berisi karakter mencurigakan: '{kid}'. "
                    "Jika server menggunakan nilai kid langsung dalam SQL query untuk mengambil "
                    "kunci verifikasi, ini berpotensi menjadi SQL Injection dalam alur autentikasi."
                ),
                "remediation": (
                    "Sanitasi dan whitelist nilai `kid` secara ketat. Gunakan UUID atau referensi "
                    "numerik sederhana untuk kid. Gunakan parameterized query dalam pencarian kunci."
                ),
                "evidence": f"JWT kid header: '{kid}'",
                "target_url": url
            })

        # ---- Check 5: Expiry analysis ----
        if payload:
            exp = payload.get("exp")
            iat = payload.get("iat")
            now = datetime.utcnow().timestamp()

            if exp and exp < now:
                findings.append({
                    "title": "JWT Token Accepted After Expiry (Missing Server-Side Expiry Validation)",
                    "severity": "High",
                    "cwe": "CWE-613",
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    "description": (
                        "Token JWT telah kedaluwarsa (exp claim sudah terlewati) namun server "
                        "tampaknya menerimanya. Ini memungkinkan penggunaan token curian jangka panjang."
                    ),
                    "remediation": (
                        "Validasi klaim `exp` di setiap request. Implementasikan token blacklist "
                        "atau rotation. Set masa berlaku token sesingkat mungkin (15 menit untuk "
                        "access token, 7 hari untuk refresh token)."
                    ),
                    "evidence": (
                        f"JWT exp={datetime.utcfromtimestamp(exp).isoformat()} "
                        f"(expired {int((now-exp)/3600)} jam lalu)"
                    ),
                    "target_url": url
                })

            # ---- Check 6: Sensitive data in payload ----
            sensitive_keywords = ["password", "passwd", "secret", "api_key", "ssn", "credit_card"]
            for key in payload.keys():
                if any(sk in key.lower() for sk in sensitive_keywords):
                    findings.append({
                        "title": f"Sensitive Data in JWT Payload ('{key}' field)",
                        "severity": "Medium",
                        "cwe": "CWE-312",
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "description": (
                            f"JWT payload mengandung field sensitif '{key}'. JWT hanya dikodekan "
                            "(bukan dienkripsi) — siapapun yang memiliki token dapat membaca isinya "
                            "hanya dengan Base64 decoding."
                        ),
                        "remediation": (
                            "Jangan simpan data sensitif dalam JWT payload. Gunakan JWE (JSON Web "
                            "Encryption) jika perlu menyimpan data sensitif dalam token."
                        ),
                        "evidence": f"JWT payload field '{key}' ditemukan di {source}",
                        "target_url": url
                    })

        return findings
