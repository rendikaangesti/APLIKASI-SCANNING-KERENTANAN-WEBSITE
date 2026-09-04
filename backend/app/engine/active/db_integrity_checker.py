import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

# Real-world Multi-Statement Stacked Injection & Privilege Boundary Probes
DDL_SIMULATION_PROBES = [
    {
        "id": "drop_database_canary",
        "instruction_type": "DDL - DROP DATABASE Boundary Audit",
        "payload": "'; DROP DATABASE vulnhunter_canary_audit_db; -- ",
        "safe_target": "vulnhunter_canary_audit_db",
        "description": "Pengujian batas hak istimewa akun database aplikasi dan resistensi terhadap multi-statement stacked SQL injection.",
        "risk_category": "Database Destruction & Administrative Privileges"
    },
    {
        "id": "drop_table_canary",
        "instruction_type": "DDL - DROP TABLE Privilege Audit",
        "payload": "'; DROP TABLE vulnhunter_canary_audit_tbl; -- ",
        "safe_target": "vulnhunter_canary_audit_tbl",
        "description": "Pengujian hak DDL DROP untuk memastikan akun database aplikasi tidak memiliki hak pemusnahan tabel.",
        "risk_category": "Structural Integrity & Table Privilege"
    },
    {
        "id": "truncate_table_canary",
        "instruction_type": "DML/DDL - TRUNCATE TABLE Audit",
        "payload": "'; TRUNCATE TABLE vulnhunter_canary_audit_tbl; -- ",
        "safe_target": "vulnhunter_canary_audit_tbl",
        "description": "Pengujian ketahanan terhadap pembersihan data massal dan validasi hak TRUNCATE pada akun database.",
        "risk_category": "Mass Data Loss & Table Integrity"
    },
    {
        "id": "alter_table_canary",
        "instruction_type": "DDL - ALTER TABLE Schema Tampering",
        "payload": "'; ALTER TABLE vulnhunter_canary_audit_tbl ADD COLUMN probe_canary text; -- ",
        "safe_target": "vulnhunter_canary_audit_tbl",
        "description": "Pengujian modifikasi skema tabel untuk memverifikasi definisi data tidak dapat dimutasi melalui SQL injection.",
        "risk_category": "Schema Tampering & Mutation"
    }
]

# Patterns indicating permission denial (Least Privilege enforced)
PERMISSION_DENIED_PATTERNS = [
    r"access denied for user '.*'@'.*' to database",
    r"drop command denied to user",
    r"permission denied for (database|table|schema)",
    r"must be owner of (database|relation)",
    r"the specified permission was not found or is denied",
    r"user does not have permission to perform this action"
]

# Patterns indicating multi-statement / stacked query rejection (Driver layer hardened)
STACKED_QUERY_REJECT_PATTERNS = [
    r"multi-statement.*not allowed",
    r"commands out of sync; you can't run this command now",
    r"cannot execute multiple queries",
    r"only one query can be executed at a time"
]

class DatabaseIntegrityAuditor:
    """
    Modul audit pengujian batas sistem dan integritas basis data (Database Integrity & Least Privilege Audit).
    Mengevaluasi lapis perlindungan data, penanganan multi-statement stacked query,
    dan penerapan Prinsip Hak Akses Terkecil (Principle of Least Privilege).
    """

    @classmethod
    async def simulate_ddl_boundary(
        cls,
        endpoint_url: str,
        param_name: str,
        probe_item: Dict[str, Any],
        http_method: str = "GET"
    ) -> Dict[str, Any]:
        """
        Mengeksekusi pengujian instruksi batas DDL / Stacked Query secara live ke target.
        """
        payload = probe_item["payload"]
        parsed = urlparse(endpoint_url)
        params = parse_qs(parsed.query)

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
            try:
                if http_method.upper() == "POST":
                    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                    res = await client.post(clean_url, data={param_name: payload})
                else:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    fuzz_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    res = await client.get(fuzz_url)

                status_code = res.status_code
                body_text = res.text.lower()

                # 1. Evaluasi Lapis Perimeter / WAF
                waf_blocked = status_code in (403, 406) or any(sig in body_text for sig in ("waf", "firewall", "blocked", "forbidden", "access denied"))

                # 2. Evaluasi Lapis Driver / Multi-Query
                stacked_blocked = any(re.search(pat, body_text) for pat in STACKED_QUERY_REJECT_PATTERNS)

                # 3. Evaluasi Hak Akses Database (Least Privilege)
                privilege_denied = any(re.search(pat, body_text) for pat in PERMISSION_DENIED_PATTERNS)

                # 4. Deteksi Error Sintaksis Standar
                syntax_error = "syntax error" in body_text or "unclosed quotation" in body_text or "sql error" in body_text

                # Kesimpulan Lapis Pertahanan
                if waf_blocked:
                    verdict = "Lapis 1 (Perimeter WAF): Diblokir dengan Aman (HTTP 403)"
                    status_type = "PROTECTED_WAF"
                    severity = "Info"
                elif stacked_blocked:
                    verdict = "Lapis 2 (Driver/ORM): Multi-statement Rejection Aktif"
                    status_type = "PROTECTED_DRIVER"
                    severity = "Info"
                elif privilege_denied:
                    verdict = "Lapis 3 (Database Privilege): Akses Ditolak (Least Privilege Terbukti Aktif)"
                    status_type = "PROTECTED_PRIVILEGE"
                    severity = "Info"
                elif syntax_error:
                    verdict = "Peringatan: Aplikasi mengekspos error SQL, berpotensi rentan jika multi-query diaktifkan"
                    status_type = "WARNING_SQL_ERROR"
                    severity = "High"
                elif status_code == 200:
                    verdict = "Lapis Aplikasi: Input ditangani secara normal / disanitasi tanpa error"
                    status_type = "SAFE_HANDLED"
                    severity = "Info"
                else:
                    verdict = f"Respon HTTP {status_code} diterima"
                    status_type = "NEUTRAL"
                    severity = "Info"

                return {
                    "instruction_type": probe_item["instruction_type"],
                    "risk_category": probe_item["risk_category"],
                    "payload_used": payload,
                    "safe_target": probe_item["safe_target"],
                    "status_code": status_code,
                    "status_type": status_type,
                    "verdict": verdict,
                    "severity": severity,
                    "waf_blocked": waf_blocked,
                    "stacked_blocked": stacked_blocked,
                    "privilege_denied": privilege_denied,
                    "syntax_error": syntax_error,
                    "endpoint_tested": endpoint_url,
                    "param_tested": param_name
                }
            except Exception as e:
                return {
                    "instruction_type": probe_item["instruction_type"],
                    "risk_category": probe_item["risk_category"],
                    "payload_used": payload,
                    "safe_target": probe_item["safe_target"],
                    "status_code": 0,
                    "status_type": "CONNECTION_ERROR",
                    "verdict": f"Gagal menghubungi target: {str(e)}",
                    "severity": "Info",
                    "waf_blocked": False,
                    "stacked_blocked": False,
                    "privilege_denied": False,
                    "syntax_error": False,
                    "endpoint_tested": endpoint_url,
                    "param_tested": param_name
                }

    async def scan_boundary_resilience(
        self, 
        discovered_urls: List[str], 
        emit_log=None
    ) -> List[Dict[str, Any]]:
        """
        Menjalankan evaluasi berkala batas integritas database selama pipeline pemindaian aktif.
        """
        findings = []

        # Pilih hingga 2 endpoint kandidat dengan parameter query
        candidates = []
        for u in discovered_urls:
            parsed = urlparse(u)
            if parse_qs(parsed.query):
                candidates.append(u)
            if len(candidates) >= 2:
                break

        if not candidates and discovered_urls:
            candidates = [discovered_urls[0]]

        for url in candidates:
            parsed = urlparse(url)
            params = parse_qs(parsed.query) or {"id": ["1"]}
            first_param = list(params.keys())[0]

            if emit_log:
                await emit_log(f"[DB-INTEGRITY] Menjalankan audit hak akses basis data (Least Privilege & Stacked Query) pada '{first_param}'...")

            for probe in DDL_SIMULATION_PROBES[:2]: # Drop DB and Drop Table
                res = await self.simulate_ddl_boundary(url, first_param, probe, http_method="GET")

                if res.get("syntax_error"):
                    findings.append({
                        "title": f"Kerentanan Batas Hak Akses Basis Data ({probe['instruction_type']})",
                        "severity": "High",
                        "cwe": "CWE-89",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "description": (
                            f"Pengujian instruksi stacked SQL '{probe['instruction_type']}' mengekspos error basis data pada parameter '{first_param}'. "
                            "Diperlukan penegakan Prinsip Hak Akses Terkecil (Least Privilege) dan penonaktifan multi-statement execution."
                        ),
                        "remediation": (
                            "1. Terapkan Principle of Least Privilege: Pastikan akun basis data aplikasi HANYA memiliki hak DML (SELECT, INSERT, UPDATE, DELETE). "
                            "Cabut seluruh hak DDL (DROP, ALTER, CREATE, TRUNCATE) dari pengguna aplikasi web.\n"
                            "2. Nonaktifkan multi-query/stacked query execution pada driver koneksi basis data.\n"
                            "3. Konfigurasikan WAF untuk memfilter kata kunci DDL berbahaya."
                        ),
                        "evidence": f"Payload: {probe['payload']} -> Response: {res['verdict']}",
                        "target_url": url
                    })
                    break

        return findings

    @classmethod
    def get_hardening_guidelines(cls) -> Dict[str, str]:
        """
        Menyediakan panduan skrip pengerasan hak akses terkecil (Least Privilege) untuk berbagai DBMS.
        """
        return {
            "MySQL / MariaDB": (
                "-- 1. Buat pengguna aplikasi dengan hak DML terbatas saja\n"
                "CREATE USER 'web_app_user'@'%' IDENTIFIED BY 'StrongPassword!2026';\n\n"
                "-- 2. Hanya berikan hak SELECT, INSERT, UPDATE, DELETE\n"
                "GRANT SELECT, INSERT, UPDATE, DELETE ON db_production.* TO 'web_app_user'@'%';\n\n"
                "-- 3. Pastikan hak DDL (DROP, ALTER, CREATE, TRUNCATE) TIDAK PERNAH diberikan\n"
                "REVOKE DROP, ALTER, CREATE, INDEX, REFERENCES ON db_production.* FROM 'web_app_user'@'%';\n"
                "FLUSH PRIVILEGES;"
            ),
            "PostgreSQL": (
                "-- 1. Buat role aplikasi terbatas\n"
                "CREATE ROLE web_app_user WITH LOGIN PASSWORD 'StrongPassword!2026';\n\n"
                "-- 2. Berikan hak koneksi & penggunaan skema\n"
                "GRANT CONNECT ON DATABASE db_production TO web_app_user;\n"
                "GRANT USAGE ON SCHEMA public TO web_app_user;\n\n"
                "-- 3. Batasi hanya DML pada tabel yang ada\n"
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO web_app_user;\n"
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO web_app_user;\n\n"
                "-- 4. Pastikan bukan Superuser dan cabut hak CREATE/DROP pada skema\n"
                "REVOKE CREATE ON SCHEMA public FROM web_app_user;"
            ),
            "Microsoft SQL Server": (
                "-- 1. Buat login dan user aplikasi\n"
                "CREATE LOGIN web_app_user WITH PASSWORD = 'StrongPassword!2026';\n"
                "USE db_production;\n"
                "CREATE USER web_app_user FOR LOGIN web_app_user;\n\n"
                "-- 2. Masukkan hanya ke role db_datareader dan db_datawriter\n"
                "ALTER ROLE db_datareader ADD MEMBER web_app_user;\n"
                "ALTER ROLE db_datawriter ADD MEMBER web_app_user;\n\n"
                "-- 3. Pastikan TIDAK dimasukkan ke db_owner atau ddladmin\n"
                "DENY ALTER ANY SCHEMA TO web_app_user;\n"
                "DENY CONTROL TO web_app_user;"
            )
        }
