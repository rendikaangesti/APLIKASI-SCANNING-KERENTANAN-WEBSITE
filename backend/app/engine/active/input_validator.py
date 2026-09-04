import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

# Comprehensive database error signatures across major engines
DB_ERROR_PATTERNS = {
    "MySQL / MariaDB": [
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"valid mysql result",
        r"check the manual that corresponds to your (mysql|mariadb) server version",
        r"myodbc"
    ],
    "PostgreSQL": [
        r"pg_query\(\): query failed:",
        r"psycopg2\.programmingerror",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
        r"pg_exec\(\)"
    ],
    "SQLite": [
        r"sqlite3::sqlexception",
        r"sqlite_error",
        r"near \".*\": syntax error",
        r"unrecognized token:",
        r"incomplete input"
    ],
    "Microsoft SQL Server": [
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"microsoft ole db provider for odbc drivers",
        r"microsoft ole db provider for sql server",
        r"incorrect syntax near"
    ],
    "Oracle": [
        r"ora-[0-9]{5}",
        r"quoted string not properly terminated"
    ],
    "Generic / ORM": [
        r"org\.hibernate\.exception\.SQLGrammarException",
        r"driver.*sql.*syntax.*error",
        r"database query error",
        r"sqlstate\["
    ]
}

# Standard input validation and resilience test probes (safe canary probes)
INPUT_TEST_PROBES = [
    {
        "id": "single_quote",
        "category": "Special Characters",
        "name": "Kutipan Tunggal (Single Quote)",
        "probe": "'",
        "purpose": "Menguji apakah sistem meloloskan karakter penutup string basis data tanpa escape/parameterisasi."
    },
    {
        "id": "double_quote_and_backtick",
        "category": "Special Characters",
        "name": "Kutipan Ganda & Backtick",
        "probe": "\" ` \\",
        "purpose": "Menguji ketahanan terhadap delimiter identifier dan karakter escape backslash."
    },
    {
        "id": "sql_comment_break",
        "category": "SQL Syntax Probes",
        "name": "Pemutus Sintaksis SQL & Komentar",
        "probe": "'--",
        "purpose": "Menguji apakah kolom input rentan terhadap pemotongan query SQL menggunakan token komentar baris."
    },
    {
        "id": "search_wildcard_bypass",
        "category": "Search Box Probes",
        "name": "Injeksi Kolom Pencarian (Wildcard Break)",
        "probe": "%' OR '1'='1",
        "purpose": "Menguji kotak pencarian yang sering menggunakan klausa LIKE '%search%' agar tidak disalahgunakan untuk logika boolean true."
    },
    {
        "id": "boolean_logic_tautology",
        "category": "SQL Syntax Probes",
        "name": "Simulasi Tautologi Boolean",
        "probe": "1' OR '1'='1' -- ",
        "purpose": "Menguji apakah validasi input mencegah modifikasi logika klausa WHERE pada filter pencarian."
    },
    {
        "id": "null_byte_probe",
        "category": "Special Characters",
        "name": "Karakter Kontrol & Null Byte",
        "probe": "%00' OR 1=1",
        "purpose": "Menguji pemfilteran karakter null terminator dan URL encoding berbahaya."
    }
]

class InputResilienceValidator:
    """
    Modul evaluasi ketahanan kolom masukan dan kotak pencarian (Input & Search Validation).
    Menguji kemampuan penyaringan, escape karakter khusus, dan penanganan kesalahan query secara aman.
    """

    @classmethod
    def match_database_errors(cls, response_text: str) -> Optional[Dict[str, str]]:
        text_lower = response_text.lower()
        for engine, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    return {
                        "engine": engine,
                        "pattern": pattern
                    }
        return None

    @classmethod
    async def test_single_endpoint(
        cls, 
        endpoint_url: str, 
        param_name: str, 
        probe_str: str,
        http_method: str = "GET"
    ) -> Dict[str, Any]:
        """
        Menjalankan pengujian ketahanan satu parameter kolom input secara real-time.
        """
        parsed = urlparse(endpoint_url)
        params = parse_qs(parsed.query)

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
            try:
                if http_method.upper() == "POST":
                    post_data = {param_name: probe_str}
                    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                    res = await client.post(clean_url, data=post_data)
                else:
                    test_params = params.copy()
                    test_params[param_name] = [probe_str]
                    new_query = urlencode(test_params, doseq=True)
                    fuzz_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    res = await client.get(fuzz_url)

                status_code = res.status_code
                resp_text = res.text
                resp_len = len(res.content)

                # Deteksi error database
                error_match = cls.match_database_errors(resp_text)

                # Deteksi WAF blocking
                is_blocked_by_waf = status_code in (403, 406) or "access denied" in resp_text.lower()

                # Deteksi refleksi unescaped
                is_reflected_raw = probe_str in resp_text

                # Penilaian status ketahanan
                if error_match:
                    resilience_status = "Vulnerable (DB Error Exposed)"
                    score_impact = "Critical"
                elif is_blocked_by_waf:
                    resilience_status = "Hardened (Blocked by WAF/Firewall)"
                    score_impact = "Secure"
                elif status_code == 400:
                    resilience_status = "Protected (Rejected as Bad Request)"
                    score_impact = "Secure"
                elif not is_reflected_raw:
                    resilience_status = "Safe (Input Sanitized/Stripped)"
                    score_impact = "Secure"
                else:
                    resilience_status = "Neutral (Input Reflected without DB Error)"
                    score_impact = "Low"

                return {
                    "param": param_name,
                    "probe": probe_str,
                    "status_code": status_code,
                    "response_length": resp_len,
                    "db_error_found": error_match is not None,
                    "matched_engine": error_match["engine"] if error_match else None,
                    "matched_pattern": error_match["pattern"] if error_match else None,
                    "is_blocked_by_waf": is_blocked_by_waf,
                    "is_reflected_raw": is_reflected_raw,
                    "resilience_status": resilience_status,
                    "score_impact": score_impact
                }
            except Exception as e:
                return {
                    "param": param_name,
                    "probe": probe_str,
                    "status_code": 0,
                    "response_length": 0,
                    "db_error_found": False,
                    "matched_engine": None,
                    "matched_pattern": None,
                    "is_blocked_by_waf": False,
                    "is_reflected_raw": False,
                    "resilience_status": f"Connection Error: {str(e)}",
                    "score_impact": "Info"
                }

    async def scan_candidate_inputs(
        self, 
        discovered_urls: List[str], 
        discovered_forms: List[Dict[str, Any]], 
        emit_log=None
    ) -> List[Dict[str, Any]]:
        """
        Menjalankan rangkaian pengujian ketahanan kolom masukan & pencarian secara komprehensif.
        """
        findings = []

        # 1. Uji parameter GET pada URLs (termasuk kotak pencarian 'q', 'search', 'keyword')
        search_params_tested = set()
        common_search_keys = {"q", "query", "search", "keyword", "s", "cari", "filter", "term"}

        for url in discovered_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Jika url tidak memiliki parameter, tambahkan parameter pencarian kandidat jika path mengindikasikan pencarian
            if not params and any(term in parsed.path.lower() for term in ("search", "find", "cari", "catalog", "produk")):
                params = {"q": ["test"]}

            for param_name in params.keys():
                param_key = f"{parsed.path}?{param_name}"
                if param_key in search_params_tested:
                    continue
                search_params_tested.add(param_key)

                is_search_field = param_name.lower() in common_search_keys

                if emit_log:
                    kind_label = "Kotak Pencarian" if is_search_field else "Kolom Masukan"
                    await emit_log(f"[INPUT-RESILIENCE] Menguji ketahanan {kind_label} '{param_name}' pada {parsed.path}...")

                # Uji probe karakter khusus dan SQL syntax
                for p in INPUT_TEST_PROBES[:4]: # Gunakan 4 probe representatif
                    res = await self.test_single_endpoint(url, param_name, p["probe"], http_method="GET")

                    if res.get("db_error_found"):
                        findings.append({
                            "title": f"Kerentanan SQL Injection pada Kolom '{param_name}' ({res['matched_engine']})",
                            "severity": "Critical",
                            "cwe": "CWE-89",
                            "owasp_category": "A03:2021-Injection",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # 9.8
                            "description": (
                                f"Kolom masukan '{param_name}' tidak menyaring karakter khusus dengan benar dan mengekspos "
                                f"pesan error internal dari mesin {res['matched_engine']}."
                            ),
                            "remediation": (
                                "Gunakan Parameterized Queries (Prepared Statements) atau Object-Relational Mapping (ORM). "
                                "Terapkan validasi ketat (allowlist) pada kolom pencarian dan sembunyikan pesan error basis data dari pengguna."
                            ),
                            "evidence": f"Probe: {p['probe']} -> Terdeteksi error pattern: '{res['matched_pattern']}'",
                            "target_url": url
                        })
                        break # Cukup 1 temuan per parameter

        # 2. Uji form inputs yang ditemukan dari crawler
        for form in discovered_forms:
            form_url = form.get("url")
            form_method = form.get("method", "GET").upper()
            form_inputs = form.get("inputs", [])

            for inp in form_inputs:
                if not inp or inp in ("csrf_token", "_token", "nonce"):
                    continue

                if emit_log:
                    await emit_log(f"[INPUT-RESILIENCE] Menguji elemen input form '{inp}' [{form_method}]...")

                probe = "'--"
                res = await self.test_single_endpoint(form_url, inp, probe, http_method=form_method)

                if res.get("db_error_found"):
                    findings.append({
                        "title": f"Kerentanan SQL Injection pada Form Input '{inp}' ({res['matched_engine']})",
                        "severity": "Critical",
                        "cwe": "CWE-89",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "description": f"Form HTML pada '{form_url}' dengan metode {form_method} membocorkan struktur basis data saat input '{inp}' dimanipulasi.",
                        "remediation": "Terapkan server-side input sanitization dan prepared statements pada pemrosesan formulir.",
                        "evidence": f"Injected: {probe} -> Signature: '{res['matched_pattern']}'",
                        "target_url": form_url
                    })
                    break

        return findings
