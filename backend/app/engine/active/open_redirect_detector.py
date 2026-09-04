"""
Open Redirect Detector
=======================
Mendeteksi kerentanan Open Redirect pada parameter URL yang mengontrol
tujuan redirect: ?url=, ?next=, ?redirect=, ?return=, ?returnUrl=, dll.

Metodologi:
  1. Probe dengan URL eksternal canary (https://evil-redirect-canary.example.com)
  2. Verifikasi Location header response
  3. 35+ payload bypass: protocol-relative, URL encoding, double encoding, null-byte
  4. Multi-parameter name coverage
"""

import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Parameter names commonly controlling redirects
# ---------------------------------------------------------------------------
REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_url", "redirect_uri",
    "return", "returnUrl", "return_url", "returnTo", "return_to",
    "goto", "go", "destination", "dest", "target", "to",
    "forward", "ref", "referrer", "referer", "backUrl", "back",
    "link", "out", "continue", "location", "rurl", "callback",
    "checkout_url", "login_url", "origin", "fallback"
]

CANARY = "https://evil-test-redirect.invalid"
CANARY_VARIANTS = [
    "https://evil-test-redirect.invalid",
    "http://evil-test-redirect.invalid",
    "//evil-test-redirect.invalid",
    "evil-test-redirect.invalid",
]

# ---------------------------------------------------------------------------
# Bypass Payloads — various encoding and protocol tricks
# ---------------------------------------------------------------------------
BYPASS_PAYLOADS = [
    # Direct
    "https://evil-test-redirect.invalid",
    "http://evil-test-redirect.invalid",
    # Protocol-relative
    "//evil-test-redirect.invalid",
    "///evil-test-redirect.invalid",
    "\\/\\/evil-test-redirect.invalid",
    # URL encoded
    "https:%2F%2Fevil-test-redirect.invalid",
    "https:%2f%2fevil-test-redirect.invalid",
    "%68%74%74%70%73%3a%2f%2fevil-test-redirect.invalid",
    # Double encoded
    "https:%252F%252Fevil-test-redirect.invalid",
    # Backslash (Windows-style)
    "https:\\\\evil-test-redirect.invalid",
    "//evil-test-redirect.invalid%2F%2E%2E",
    # Null byte injection
    "https://evil-test-redirect.invalid%00",
    "https://evil-test-redirect.invalid%0a",
    # Subdomain confusion (bypass allowlist)
    "https://legitimate.com.evil-test-redirect.invalid",
    "https://evil-test-redirect.invalid?legitimate.com",
    "https://evil-test-redirect.invalid#legitimate.com",
    # @ trick (credentials)
    "https://legitimate.com@evil-test-redirect.invalid",
    # Unicode / IDN homograph
    "https://еvil-test-redirect.invalid",   # Cyrillic е
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # javascript: (XSS via redirect)
    "javascript:alert(document.domain)",
    "javascript://evil-test-redirect.invalid/%0aalert(1)",
    # CRLF injection in redirect
    "https://legitimate.com%0d%0aLocation:https://evil-test-redirect.invalid",
    # Relative-path confusion
    "/%2Fevil-test-redirect.invalid",
    "/%5Cevil-test-redirect.invalid",
]


def _is_redirected_externally(location: Optional[str], base_host: str) -> bool:
    """Return True if the Location header points outside the base host."""
    if not location:
        return False
    for canary in CANARY_VARIANTS:
        if canary.lower().split("//")[-1].split("/")[0] in location.lower():
            return True
    try:
        parsed = urlparse(location if location.startswith("http") else f"http:{location}")
        return parsed.hostname is not None and base_host not in parsed.hostname
    except Exception:
        return False


class OpenRedirectDetector:
    """
    Fuzzer Open Redirect berbasis HTTP Location header tracking.
    """

    async def scan_urls(
        self,
        urls: List[str],
        forms: Optional[List[Dict[str, Any]]] = None,
        emit_log=None
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tested_keys: set = set()

        async with httpx.AsyncClient(
            verify=False,
            timeout=8.0,
            follow_redirects=False   # PENTING: jangan ikuti redirect supaya bisa cek Location
        ) as client:
            # ---- 1. Cari parameter redirect di existing URLs ----
            for url in urls:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param_name in list(params.keys()):
                    if param_name.lower() not in [p.lower() for p in REDIRECT_PARAMS]:
                        continue

                    key = f"REDIR:{parsed.netloc}{parsed.path}:{param_name}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    finding = await self._fuzz_param(
                        client, url, parsed, params, param_name, emit_log
                    )
                    if finding:
                        findings.append(finding)

            # ---- 2. Inject redirect params pada semua URL (parameter fishing) ----
            for url in urls[:10]:  # Limit to avoid too many requests
                parsed = urlparse(url)
                base_host = parsed.hostname or ""

                for rp in REDIRECT_PARAMS[:8]:  # Most common ones
                    key = f"REDIR_INJECT:{parsed.netloc}{parsed.path}:{rp}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    for payload in BYPASS_PAYLOADS[:5]:  # Top 5 most effective
                        test_params = dict(parse_qs(parsed.query))
                        test_params[rp] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        fuzz_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))

                        if emit_log:
                            await emit_log(f"[OPENREDIR] Injecting param '{rp}' on {parsed.path}")

                        try:
                            res = await client.get(fuzz_url, timeout=6.0)
                            if res.status_code in (301, 302, 303, 307, 308):
                                location = res.headers.get("location", "")
                                if _is_redirected_externally(location, base_host):
                                    findings.append(self._build_finding(
                                        rp, payload, location, fuzz_url
                                    ))
                                    break
                        except Exception:
                            continue

        return findings

    async def _fuzz_param(
        self, client, url, parsed, params, param_name, emit_log
    ) -> Optional[Dict[str, Any]]:
        base_host = parsed.hostname or ""

        for payload in BYPASS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            fuzz_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            if emit_log:
                await emit_log(
                    f"[OPENREDIR-PROBE] Testing param '{param_name}' "
                    f"payload='{payload[:50]}'"
                )

            try:
                res = await client.get(fuzz_url, timeout=6.0)
                if res.status_code in (301, 302, 303, 307, 308):
                    location = res.headers.get("location", "")
                    if _is_redirected_externally(location, base_host):
                        return self._build_finding(param_name, payload, location, fuzz_url)
            except Exception:
                continue

        return None

    def _build_finding(
        self, param: str, payload: str, location: str, fuzz_url: str
    ) -> Dict[str, Any]:
        return {
            "title": f"Open Redirect via Parameter '{param}'",
            "severity": "Medium",
            "cwe": "CWE-601",
            "owasp_category": "A01:2021-Broken Access Control",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1
            "description": (
                f"Endpoint menerima URL eksternal pada parameter '{param}' tanpa validasi, "
                "memungkinkan penyerang mengarahkan pengguna ke situs phishing atau malware. "
                "Dieksploitasi dalam serangan spear-phishing, token hijacking OAuth, dan bypass "
                "SSRF melalui chaining redirect."
            ),
            "remediation": (
                "Implementasikan allowlist URL tujuan redirect yang ketat. Jangan gunakan input "
                "pengguna secara langsung sebagai tujuan redirect. Gunakan indirect reference map "
                "(nomor indeks → URL preset) atau validasi host terhadap daftar domain tepercaya."
            ),
            "evidence": (
                f"Parameter '{param}' dengan payload '{payload[:80]}' "
                f"menghasilkan redirect ke: {location}"
            ),
            "target_url": fuzz_url
        }
