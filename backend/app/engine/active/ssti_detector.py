"""
SSTI Detector — Server-Side Template Injection
================================================
Mendeteksi kerentanan Server-Side Template Injection (SSTI) pada:
  • Jinja2 / Flask (Python)
  • Twig (PHP)
  • Freemarker (Java)
  • Pebble (Java)
  • Mako (Python)
  • Smarty (PHP)
  • Ruby ERB / Slim

Metodologi:
  1. Mathematical expression probes (disambiguasi antar engine)
  2. String evaluation probes (konfirmasi eksekusi template)
  3. Multi-level fallback dengan variasi encoding
"""

import httpx
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Probe Definitions — setiap engine punya ekspresi matematika unik
# ---------------------------------------------------------------------------
SSTI_PROBES = [
    {
        "name": "Jinja2 / Mako (Python)",
        "payloads": [
            {"inject": "{{7*7}}", "expected": "49"},
            {"inject": "{{7*'7'}}", "expected": "7777777"},   # Jinja2 string multiply
            {"inject": "${7*7}", "expected": "49"},             # Mako
        ],
        "cwe": "CWE-1336",
        "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
        "owasp": "A03:2021-Injection",
        "desc": (
            "Server-Side Template Injection (SSTI) terdeteksi pada Python template engine (Jinja2/Mako). "
            "Penyerang dapat mengeksekusi kode Python arbitrer di server — termasuk membaca file sistem, "
            "menjalankan perintah OS, dan mengekstrak kredensial environment."
        ),
        "remediation": (
            "Jangan pernah merender input pengguna secara langsung melalui `render_template_string()` atau "
            "template engine tanpa sandboxing. Gunakan `jinja2.sandbox.SandboxedEnvironment` dan validasi "
            "input secara ketat sebelum dioper ke layer template."
        )
    },
    {
        "name": "Twig (PHP)",
        "payloads": [
            {"inject": "{{7*7}}", "expected": "49"},
            {"inject": "{{7*'7'}}", "expected": "49"},   # Twig: int × string = int
        ],
        "cwe": "CWE-1336",
        "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "owasp": "A03:2021-Injection",
        "desc": (
            "SSTI terdeteksi pada Twig template engine (PHP). Penyerang dapat memanfaatkan Twig filter chain "
            "untuk mengeksekusi shell command PHP melalui `|map` atau `_invoke` chain attacks."
        ),
        "remediation": (
            "Aktifkan `Twig\\Sandbox\\SecurityPolicy` dan batasi akses ke method/property berbahaya. "
            "Hindari merender variabel tidak-trusted langsung ke template Twig."
        )
    },
    {
        "name": "Freemarker / Pebble (Java)",
        "payloads": [
            {"inject": "${7*7}", "expected": "49"},
            {"inject": "#{7*7}", "expected": "49"},
            {"inject": "<#assign x=7*7>${x}", "expected": "49"},
        ],
        "cwe": "CWE-1336",
        "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "owasp": "A03:2021-Injection",
        "desc": (
            "SSTI terdeteksi pada Java template engine (Freemarker/Pebble). "
            "Eksploitasi lanjutan memungkinkan eksekusi kode Java arbitrer via `freemarker.template.utility.Execute`."
        ),
        "remediation": (
            "Gunakan Freemarker Configuration dengan `setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)` "
            "dan nonaktifkan `?new()` built-in. Isolasi template dalam sandbox ClassLoader."
        )
    },
    {
        "name": "Ruby ERB / Slim",
        "payloads": [
            {"inject": "<%= 7*7 %>", "expected": "49"},
            {"inject": "${7*7}", "expected": "49"},
        ],
        "cwe": "CWE-1336",
        "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "owasp": "A03:2021-Injection",
        "desc": (
            "SSTI terdeteksi pada Ruby ERB template. Penyerang dapat mengeksekusi Ruby code arbitrer "
            "termasuk `system()` call untuk remote code execution."
        ),
        "remediation": (
            "Sanitasi semua user input sebelum diteruskan ke ERB.new(). Gunakan `erb.result(binding)` "
            "dengan binding terbatas. Pertimbangkan penggunaan Liquid atau Mustache (logic-less templates)."
        )
    },
    {
        "name": "Smarty (PHP)",
        "payloads": [
            {"inject": "{7*7}", "expected": "49"},
            {"inject": "{math equation='7*7'}", "expected": "49"},
        ],
        "cwe": "CWE-1336",
        "severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "owasp": "A03:2021-Injection",
        "desc": (
            "SSTI terdeteksi pada Smarty template engine (PHP). Penyerang dapat mengeksekusi PHP functions "
            "melalui `{php}` tag atau `{eval}` function."
        ),
        "remediation": (
            "Aktifkan Smarty Sandbox Mode (`$smarty->security_policy = new Smarty_Security($smarty)`). "
            "Nonaktifkan `{php}`, `{include_php}`, dan tag berbahaya lainnya."
        )
    }
]

# ---------------------------------------------------------------------------
# Encoding Bypass Wrappers
# ---------------------------------------------------------------------------
def make_encoded_variants(payload: str) -> List[str]:
    """Return URL-encoded variants of the payload."""
    import urllib.parse
    variants = [payload]
    variants.append(urllib.parse.quote(payload))
    variants.append(urllib.parse.quote(payload, safe=""))
    return list(dict.fromkeys(variants))  # deduplicate


class SSTIDetector:
    """
    Deteksi Server-Side Template Injection (SSTI) pada parameter URL dan form input.
    """

    async def scan_urls(
        self,
        urls: List[str],
        forms: Optional[List[Dict[str, Any]]] = None,
        emit_log=None
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tested_keys: set = set()

        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            # ---- 1. Test URL query parameters ----
            for url in urls:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys()):
                    param_key = f"SSTI:{parsed.netloc}{parsed.path}:{param_name}"
                    if param_key in tested_keys:
                        continue
                    tested_keys.add(param_key)

                    finding = await self._probe_parameter(
                        client, url, parsed, params, param_name, emit_log
                    )
                    if finding:
                        findings.append(finding)

            # ---- 2. Test discovered HTML forms ----
            if forms:
                for form in forms:
                    form_url = form.get("url")
                    method = form.get("method", "GET").upper()
                    inputs = form.get("inputs", [])
                    if not form_url or not inputs:
                        continue

                    for inp in inputs:
                        form_key = f"SSTI_FORM:{form_url}:{inp}"
                        if form_key in tested_keys:
                            continue
                        tested_keys.add(form_key)

                        finding = await self._probe_form_input(
                            client, form_url, method, inputs, inp, emit_log
                        )
                        if finding:
                            findings.append(finding)

        return findings

    async def _probe_parameter(
        self, client, url, parsed, params, param_name, emit_log
    ) -> Optional[Dict[str, Any]]:
        for engine_probe in SSTI_PROBES:
            for payload_def in engine_probe["payloads"]:
                inject = payload_def["inject"]
                expected = payload_def["expected"]

                for encoded_inject in make_encoded_variants(inject)[:2]:  # max 2 variants
                    test_params = params.copy()
                    test_params[param_name] = [encoded_inject]
                    new_query = urlencode(test_params, doseq=True)
                    fuzz_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    if emit_log:
                        await emit_log(
                            f"[SSTI-PROBE] Testing {engine_probe['name']} on "
                            f"'{param_name}' payload='{inject}' expecting='{expected}'"
                        )

                    try:
                        res = await client.get(fuzz_url, timeout=8.0)
                        if expected in res.text:
                            return {
                                "title": f"Server-Side Template Injection (SSTI) — {engine_probe['name']} in '{param_name}'",
                                "severity": engine_probe["severity"],
                                "cwe": engine_probe["cwe"],
                                "owasp_category": engine_probe["owasp"],
                                "cvss_vector": engine_probe["cvss_vector"],
                                "description": engine_probe["desc"],
                                "remediation": engine_probe["remediation"],
                                "evidence": (
                                    f"Payload '{inject}' melalui parameter '{param_name}' "
                                    f"menghasilkan output '{expected}' dalam response body — "
                                    f"membuktikan eksekusi ekspresi template di server."
                                ),
                                "target_url": fuzz_url
                            }
                    except Exception:
                        continue

        return None

    async def _probe_form_input(
        self, client, form_url, method, inputs, inp, emit_log
    ) -> Optional[Dict[str, Any]]:
        for engine_probe in SSTI_PROBES[:2]:  # Jinja2 + Twig — paling umum
            for payload_def in engine_probe["payloads"][:1]:
                inject = payload_def["inject"]
                expected = payload_def["expected"]

                form_data = {i: "test" for i in inputs}
                form_data[inp] = inject

                if emit_log:
                    await emit_log(
                        f"[SSTI-FORM] Testing {engine_probe['name']} on form '{inp}' "
                        f"at {form_url} ({method})"
                    )

                try:
                    if method == "POST":
                        res = await client.post(form_url, data=form_data, timeout=8.0)
                    else:
                        res = await client.get(form_url, params=form_data, timeout=8.0)

                    if expected in res.text:
                        return {
                            "title": f"Server-Side Template Injection (SSTI) — {engine_probe['name']} in Form Field '{inp}'",
                            "severity": engine_probe["severity"],
                            "cwe": engine_probe["cwe"],
                            "owasp_category": engine_probe["owasp"],
                            "cvss_vector": engine_probe["cvss_vector"],
                            "description": engine_probe["desc"],
                            "remediation": engine_probe["remediation"],
                            "evidence": (
                                f"Form input '{inp}' dengan payload '{inject}' menghasilkan "
                                f"output '{expected}' — eksekusi template terkonfirmasi."
                            ),
                            "target_url": form_url
                        }
                except Exception:
                    continue

        return None
