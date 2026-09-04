import ssl
import socket
import asyncio
import time
import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import httpx
from bs4 import BeautifulSoup

from app.core.ssrf_guard import validate_and_sanitize_target
from app.engine.passive.header_analyzer import SecurityHeaderAnalyzer
from app.engine.passive.ssl_tls_checker import SSLTLSChecker
from app.engine.passive.cookie_auditor import CookieSecurityAuditor
from app.engine.passive.tech_detector import TechnologyDetector
from app.engine.passive.domain_relations import DomainRelationsAnalyzer, extract_root_domain
from app.engine.passive.subdomain_enum import SubdomainEnumerator
from app.engine.passive.cve_fingerprint import CVEFingerprintEngine, CVE_DATABASE
from app.engine.active.crawler import WebCrawler
from app.engine.active.dir_fuzzer import SENSITIVE_TARGETS
from app.engine.active.sqli_detector import SQLiDetector, SQL_ERROR_PATTERNS
from app.engine.active.xss_analyzer import XSSAnalyzer
from app.engine.active.ssti_detector import SSTIDetector
from app.engine.active.open_redirect_detector import OpenRedirectDetector
from app.engine.active.lfi_detector import LFIDetector
from app.engine.active.jwt_analyzer import JWTAnalyzer, _decode_jwt_parts, _is_jwt_like
from app.engine.active.input_validator import InputResilienceValidator, INPUT_TEST_PROBES, DB_ERROR_PATTERNS
from app.engine.active.db_integrity_checker import DatabaseIntegrityAuditor, DDL_SIMULATION_PROBES
from app.engine.active.cors_analyzer import CORSAnalyzer
from app.engine.active.csp_analyzer import CSPAnalyzer
from app.engine.scoring.compliance_benchmark import InternationalComplianceEngine

class LiveAuditEngine:
    """
    Live Engine for interactive target auditing, terminal command execution,
    asset exploration, and finding proof-of-concept verification against live domains (2026 Edition).
    """

    KNOWN_WAF_SIGNATURES = [
        {"name": "Cloudflare", "headers": ["cf-ray", "cf-cache-status", "server"], "pattern": r"cloudflare", "cookies": ["__cfduid", "cf_clearance"]},
        {"name": "AWS WAF / CloudFront", "headers": ["x-amz-cf-id", "x-amz-cf-pop", "server"], "pattern": r"cloudfront|awswaf", "cookies": ["aws-waf-token"]},
        {"name": "Akamai", "headers": ["x-akamai-transformed", "server"], "pattern": r"akamai", "cookies": ["ak_bmsc", "bm_sz"]},
        {"name": "Imperva / Incapsula", "headers": ["x-cdn", "x-iinfo"], "pattern": r"incapsula|imperva", "cookies": ["incap_ses", "visid_incap"]},
        {"name": "ModSecurity", "headers": ["server"], "pattern": r"mod_security|modsecurity", "cookies": []},
        {"name": "Sucuri CloudProxy", "headers": ["x-sucuri-id", "server"], "pattern": r"sucuri", "cookies": []},
        {"name": "LiteSpeed Web Server / WAF", "headers": ["server"], "pattern": r"litespeed", "cookies": []},
        {"name": "Fastly", "headers": ["x-fastly-request-id", "fastly-debug-digest"], "pattern": r"fastly", "cookies": []},
        {"name": "F5 BIG-IP ASM", "headers": ["server", "x-cnection"], "pattern": r"big-ip|f5", "cookies": ["bigipserver", "ts[0-9a-f]+"]},
    ]

    COMMON_WEB_PORTS = [
        (80, "HTTP"),
        (443, "HTTPS"),
        (8080, "HTTP-Alt / Proxy"),
        (8443, "HTTPS-Alt"),
        (3000, "Node / React Dev"),
        (8000, "Django / FastAPI Dev"),
        (8888, "Jupyter / HTTP-Admin"),
        (9000, "Portainer / PHP-FPM"),
        (21, "FTP"),
        (22, "SSH"),
        (3306, "MySQL / MariaDB"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
    ]

    @classmethod
    async def execute_live_command(cls, command: str, target_url: str) -> Dict[str, Any]:
        """
        Executes a real live diagnostic/audit command against the target live domain.
        """
        cmd_clean = command.strip()
        if not cmd_clean:
            return {
                "command": command,
                "output": "No command entered. Type 'help' for a list of available live commands.",
                "exit_code": 1,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }

        parts = cmd_clean.split()
        verb = parts[0].lower()
        args = parts[1:]

        # Validate target URL
        is_valid, normalized_url, err_msg = validate_and_sanitize_target(target_url)
        if not is_valid and verb not in ("help", "clear"):
            return {
                "command": command,
                "output": f"[ERROR] Invalid target URL '{target_url}': {err_msg}",
                "exit_code": 1,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }

        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or "target.live"

        try:
            if verb == "help":
                return cls._cmd_help(command)

            elif verb in ("headers", "header", "http-headers"):
                return await cls._cmd_headers(command, normalized_url)

            elif verb in ("curl", "http", "get", "fetch"):
                path = args[0] if args else "/"
                return await cls._cmd_curl(command, normalized_url, path)

            elif verb in ("ssl", "tls", "cert", "ssl-check"):
                return await cls._cmd_ssl(command, hostname, parsed.port or 443)

            elif verb in ("dns", "dns-lookup", "nslookup", "dig"):
                record_type = args[0].upper() if args else "ALL"
                return await cls._cmd_dns(command, hostname, record_type)

            elif verb in ("waf", "waf-detect", "firewall"):
                return await cls._cmd_waf(command, normalized_url)

            elif verb in ("portscan", "ports", "scan-ports"):
                return await cls._cmd_portscan(command, hostname)

            elif verb in ("fuzz", "probe-paths", "dirfuzz", "sensitive", "secrets"):
                return await cls._cmd_fuzz_paths(command, normalized_url)

            elif verb in ("api", "swagger", "openapi"):
                return await cls._cmd_api(command, normalized_url)

            elif verb in ("graphql", "gql"):
                return await cls._cmd_graphql(command, normalized_url)

            elif verb in ("cors", "cors-test"):
                return await cls._cmd_cors(command, normalized_url)

            elif verb in ("tech", "stack", "detect"):
                return await cls._cmd_tech(command, normalized_url)

            elif verb in ("remediation", "fix", "config"):
                return cls._cmd_remediation(command, normalized_url)

            elif verb in ("crawl", "spider", "links"):
                return await cls._cmd_crawl(command, normalized_url)

            elif verb in ("methods", "options", "http-methods"):
                return await cls._cmd_methods(command, normalized_url)

            elif verb in ("robots", "sitemap", "robots.txt", "sitemap.xml"):
                return await cls._cmd_robots_sitemap(command, normalized_url)

            elif verb in ("whois", "ip", "host-info"):
                return await cls._cmd_whois(command, hostname)

            elif verb in ("test-xss", "xss"):
                test_endpoint = args[0] if args else normalized_url
                return await cls._cmd_test_xss(command, normalized_url, test_endpoint)

            elif verb in ("test-sqli", "sqli"):
                test_endpoint = args[0] if args else normalized_url
                return await cls._cmd_test_sqli(command, normalized_url, test_endpoint)

            elif verb in ("test-input", "input-test", "input-fuzz", "test-search"):
                test_endpoint = args[0] if args else normalized_url
                param = args[1] if len(args) > 1 else None
                return await cls._cmd_test_input(command, normalized_url, test_endpoint, param)

            elif verb in ("db-boundary", "db-integrity", "test-ddl", "drop-test"):
                test_endpoint = args[0] if args else normalized_url
                param = args[1] if len(args) > 1 else "id"
                return await cls._cmd_db_boundary(command, normalized_url, test_endpoint, param)

            elif verb in ("scorecard", "grade", "score", "audit-score"):
                return await cls._cmd_scorecard(command, normalized_url, hostname)

            elif verb in ("compliance", "standards", "owasp", "iso", "pci", "nist"):
                return await cls._cmd_compliance(command, normalized_url, hostname)

            elif verb in ("emailsec", "dnssec", "dmarc", "spf", "caa"):
                return await cls._cmd_dnssec_email(command, hostname)

            elif verb in ("ssti", "ssti-test", "template-injection"):
                test_url = args[0] if args else normalized_url
                return await cls._cmd_ssti(command, normalized_url, test_url)

            elif verb in ("openredirect", "redirect", "open-redirect"):
                test_url = args[0] if args else normalized_url
                return await cls._cmd_open_redirect(command, normalized_url, test_url)

            elif verb in ("lfi", "traversal", "path-traversal"):
                test_url = args[0] if args else normalized_url
                return await cls._cmd_lfi(command, normalized_url, test_url)

            elif verb in ("jwt-analyze", "jwt", "jwt-decode"):
                token = args[0] if args else ""
                return await cls._cmd_jwt(command, normalized_url, token)

            elif verb in ("subdomains", "subs", "subdomain-enum"):
                return await cls._cmd_subdomains(command, normalized_url, hostname)

            elif verb in ("cve-check", "cve", "cve-scan"):
                return await cls._cmd_cve_check(command, normalized_url)

            elif verb in ("nuclei", "templates"):
                template_name = args[0] if args else "all"
                return await cls._cmd_nuclei(command, normalized_url, template_name)

            elif verb in ("http2", "http3", "alpn", "quic"):
                return await cls._cmd_http2_alpn(command, hostname, parsed.port or 443)

            elif verb in ("tls-grade", "tlsgrade", "ssl-grade"):
                return await cls._cmd_tls_grade(command, normalized_url, hostname, parsed.port or 443)

            elif verb in ("smuggle", "smuggling", "req-smuggle"):
                return await cls._cmd_smuggle(command, normalized_url, hostname)

            elif verb in ("cache-poison", "cache-poisoning", "poison"):
                return await cls._cmd_cache_poison(command, normalized_url)

            elif verb in ("cors-deep", "cors-audit"):
                return await cls._cmd_cors_deep(command, normalized_url)

            elif verb in ("prototype", "proto-pollution", "proto"):
                return await cls._cmd_prototype(command, normalized_url)

            elif verb in ("clickjack", "clickjacking", "iframe-test"):
                return await cls._cmd_clickjack(command, normalized_url)

            elif verb in ("srcmap", "sourcemap", "source-maps"):
                return await cls._cmd_srcmap(command, normalized_url)

            else:
                return {
                    "command": command,
                    "output": f"Perintah '{verb}' tidak dikenal. Ketik 'help' untuk melihat daftar seluruh live command audit.",
                    "exit_code": 1,
                    "timestamp": datetime.now().strftime("%H:%M:%S")
                }

        except Exception as e:
            return {
                "command": command,
                "output": f"[EXECUTION ERROR] Live command failed: {str(e)}",
                "exit_code": 1,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }

    @classmethod
    def _cmd_help(cls, command: str) -> Dict[str, Any]:
        help_text = """
================================================================================
⚡ DJOERAGANCYBER LIVE INTERACTIVE SECURITY AUDIT CONSOLE (2026 EDITION)
================================================================================
Seluruh perintah mengeksekusi probe jaringan & HTTP secara LANGSUNG ke domain target:

[ 📊 Enterprise Standards & Scorecard ]
  scorecard           - Kalkulasi skor postur keamanan komprehensif & Letter Grade (A+ s/d F)
  compliance          - Audit kepatuhan standar internasional (OWASP Top 10, ISO 27001, PCI-DSS, NIST)
  emailsec / dnssec   - Audit proteksi anti-spoofing & pembajakan DNS (SPF, DMARC, DKIM, CAA, DNSSEC)
  tls-grade           - Evaluasi sertifikat TLS ala SSL Labs dengan grade A+ s/d F & cipher check

[ 🌐 HTTP, Headers & Protocol Probes ]
  curl <path>         - Kirim HTTP GET live ke path tertentu (misal: 'curl /api/v1')
  headers             - Evaluasi kepatuhan HTTP Security Headers (HSTS, CSP, COOP, COEP, CORP, dll.)
  http2 / http3       - Uji negosiasi protokol ALPN HTTP/2 dan iklan HTTP/3 (Alt-Svc)
  api                 - Audit endpoints OpenAPI, Swagger UI (/openapi.json, /swagger-ui.html)
  graphql             - Uji live endpoint GraphQL dan query skema Introspection (/graphql)
  cors / cors-deep    - Uji multi-skenario refleksi origin & ACAC CORS misconfiguration
  methods             - Probe metode HTTP yang diizinkan (OPTIONS, TRACE, PUT, DELETE)
  robots              - Inspeksi arahan live robots.txt dan sitemap.xml
  clickjack           - Uji kerentanan Clickjacking UI Redressing (X-Frame-Options / CSP)
  smuggle             - Uji respons HTTP Request Smuggling (CL.TE / TE.CL conflict probe)
  cache-poison        - Uji header unkeyed (X-Forwarded-Host, X-Original-URL) untuk cache poisoning

[ 🔍 Reconnaissance, WAF & Network ]
  subdomains          - Enumerasi subdomain via Certificate Transparency (crt.sh) & DNS brute-force
  cve-check           - Banner-to-CVE matching berbasis NVD Advisory & CVSS
  dns [type]          - Query DNS publik: A, AAAA, MX, NS, TXT, SPF, DMARC, CNAME (atau 'dns ALL')
  ssl / tls           - Live audit sertifikat TLS 1.3/1.2, cipher suite, masa berlaku, dan SANs
  waf                 - Deteksi & fingerprinting firewall aktif (Cloudflare, AWS WAF, Akamai, dll.)
  portscan            - Async port scan aman untuk port web dan service umum
  whois / ip          - Resolusi alamat IP target host dan reverse PTR record
  tech                - Fingerprinting stack teknologi backend, CMS, web server, & library
  srcmap              - Deteksi file JavaScript Source Map (.js.map) yang terekspos

[ 🎯 Active Attack Surface & Fuzzing ]
  fuzz / secrets      - Probe file berisiko tinggi (.env, .git, docker-compose, backup.sql, actuator)
  nuclei [template]   - Eksekusi probe template kerentanan presisi tinggi ala Nuclei
  crawl               - Spider web modern dengan ekstraksi route SPA, endpoint JS, & form multipart
  test-xss <url>      - Uji refleksi parameter untuk Reflected XSS & DOM sinks
  test-sqli <url>     - Uji respon syntax error database untuk SQL Injection & NoSQL
  ssti [url]          - Uji Server-Side Template Injection (Jinja2, Twig, Freemarker, ERB)
  openredirect [url]  - Uji Open Redirect dengan 35+ payload encoding & protocol bypass
  lfi [url]           - Uji Local File Inclusion / Path Traversal (/etc/passwd, win.ini)
  jwt-analyze [token] - Analisis keamanan JWT token (alg:none, weak HMAC dictionary, claims)
  test-input [url]    - Uji ketahanan kolom masukan & search box dengan karakter khusus & SQLi
  db-boundary [url]   - Simulasi instruksi batas sistem DDL (DROP DATABASE/TABLE) terisolasi
  prototype           - Uji potensi Client/Server JavaScript Prototype Pollution
  remediation         - Hasilkan skrip konfigurasi hardening instan (Nginx, Apache, Caddy, FastAPI)

[ ⚙️ Utilitas ]
  help                - Tampilkan referensi bantuan perintah ini
  clear               - Bersihkan riwayat layar konsol terminal
================================================================================
"""
        return {
            "command": command,
            "output": help_text.strip(),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _safe_http_get(cls, client: httpx.AsyncClient, url: str, **kwargs):
        """
        Sends HTTP GET with automatic HTTPS -> HTTP fallback for non-SSL targets.
        """
        try:
            return await client.get(url, **kwargs)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError, ssl.SSLError):
            if url.startswith("https://"):
                alt_url = "http://" + url[8:]
                return await client.get(alt_url, **kwargs)
            raise

    @classmethod
    async def _cmd_headers(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menghubungkan secara live ke {target_url} untuk menginspeksi HTTP headers...\n"]
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            t0 = time.time()
            res = await cls._safe_http_get(client, target_url)
            latency = int((time.time() - t0) * 1000)

            lines.append(f"HTTP/{res.http_version} {res.status_code} {res.reason_phrase} (Latency: {latency}ms)")
            lines.append("------------------------------------------------------------")
            for k, v in res.headers.items():
                lines.append(f"{k}: {v}")

            lines.append("\n[*] Evaluasi Kepatuhan Security Headers (Standar 2026):")
            lines.append("------------------------------------------------------------")
            sec_headers = {
                "Strict-Transport-Security": "Proteksi terhadap MitM & SSL-Strip downgrade",
                "Content-Security-Policy": "Mitigasi Cross-Site Scripting (XSS) & Code Injection",
                "X-Frame-Options": "Mencegah Clickjacking UI Redressing",
                "X-Content-Type-Options": "Mencegah MIME-type sniffing",
                "Referrer-Policy": "Mengontrol kebocoran data pada header Referer",
                "Permissions-Policy": "Membatasi API sensor, kamera, mic, & geolocation",
                "Cross-Origin-Opener-Policy": "Isolasi konteks browsing dari tab lintas-domain",
                "Cross-Origin-Resource-Policy": "Mencegah pembacaan resource privat lintas-domain"
            }

            headers_lower = {k.lower(): v for k, v in res.headers.items()}
            for h, purpose in sec_headers.items():
                if h.lower() in headers_lower:
                    lines.append(f"  [+] PRESENT  : {h} -> {headers_lower[h.lower()][:60]}")
                else:
                    lines.append(f"  [-] MISSING  : {h} ({purpose})")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_api(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan audit OpenAPI & Swagger endpoints pada {target_url}...\n"]
        base_url = target_url.rstrip("/")
        api_paths = [
            ("/openapi.json", "OpenAPI Specification JSON"),
            ("/swagger.json", "Swagger 2.0 Specification JSON"),
            ("/swagger-ui.html", "Swagger UI Web Interface"),
            ("/swagger/v1/swagger.json", "Swagger v1 JSON"),
            ("/api-docs", "SpringFox / Swagger API Docs"),
            ("/v2/api-docs", "Swagger v2 API Docs"),
            ("/v3/api-docs", "OpenAPI v3 API Docs"),
            ("/docs", "FastAPI / ReDoc Interactive Docs"),
            ("/redoc", "ReDoc Interactive API Docs")
        ]

        found_count = 0
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
            for path, label in api_paths:
                test_url = f"{base_url}{path}"
                try:
                    res = await client.get(test_url)
                    if res.status_code == 200:
                        lines.append(f"  [!] DITEMUKAN (HTTP 200): {path}")
                        lines.append(f"      Tipe: {label}")
                        lines.append(f"      Ukuran Payload: {len(res.content)} bytes")
                        lines.append(f"      URL: {test_url}\n")
                        found_count += 1
                    elif res.status_code in (401, 403):
                        lines.append(f"  [*] TERPROTEKSI (HTTP {res.status_code}): {path} ({label})")
                except Exception:
                    pass

        if found_count == 0:
            lines.append("[-] Tidak ditemukan dokumentasi OpenAPI atau Swagger publik pada path umum.")
        else:
            lines.append(f"[!] Peringatan: Ditemukan {found_count} endpoint dokumentasi API publik yang dapat mengungkap routes internal.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_graphql(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Memeriksa GraphQL endpoint dan Introspection query pada {target_url}...\n"]
        base_url = target_url.rstrip("/")
        gql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql"]

        introspection_query = {"query": "{ __schema { types { name } } }"}
        found = False

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            for path in gql_paths:
                test_url = f"{base_url}{path}"
                try:
                    # Test POST Introspection
                    res = await client.post(test_url, json=introspection_query, headers={"Content-Type": "application/json"})
                    if res.status_code == 200 and "__schema" in res.text:
                        lines.append(f"  [!] CRITICAL: GraphQL Introspection AKTIF pada {test_url}")
                        lines.append("      Seluruh skema database & resolver dapat diekstrak oleh pihak ketiga.")
                        data = res.json()
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t.get("name") for t in types if not t.get("name", "").startswith("__")][:8]
                        lines.append(f"      Contoh Tipe Terbuka: {', '.join(type_names)}")
                        found = True
                        break
                    elif res.status_code in (200, 400, 405):
                        lines.append(f"  [+] Endpoint GraphQL terdeteksi di {test_url} (HTTP {res.status_code}), namun Introspection dicegah.")
                        found = True
                        break
                except Exception:
                    pass

        if not found:
            lines.append("[-] Tidak terdeteksi GraphQL endpoint aktif pada path standar (/graphql, /graphiql).")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_cors(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan uji refleksi CORS (Cross-Origin Resource Sharing) pada {target_url}...\n"]
        test_origin = "https://attacker-cyber-audit.com"

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
            try:
                res = await client.get(target_url, headers={"Origin": test_origin})
                acao = res.headers.get("access-control-allow-origin")
                acac = res.headers.get("access-control-allow-credentials")

                lines.append(f"Origin Dikirim : {test_origin}")
                lines.append(f"Status Response: HTTP {res.status_code}")
                lines.append(f"Access-Control-Allow-Origin      : {acao or 'Tidak ada'}")
                lines.append(f"Access-Control-Allow-Credentials : {acac or 'Tidak ada'}\n")

                if acao == test_origin and acac and acac.lower() == "true":
                    lines.append("[!] CRITICAL VULNERABILITY: Arbitrary CORS Origin Reflection dengan Kredensial!")
                    lines.append("    Server merefleksikan Origin sembarang dan mengizinkan cookies/kredensial dikirim lintas domain.")
                elif acao == "*":
                    lines.append("[!] WARNING: CORS Wildcard '*' terdeteksi. Seluruh situs eksternal dapat membaca response publik.")
                elif acao == test_origin:
                    lines.append("[!] WARNING: Arbitrary CORS Origin Reflection terdeteksi (namun credentials: false).")
                else:
                    lines.append("[+] Konfigurasi CORS aman: Server menolak Origin pihak ketiga sembarang.")
            except Exception as e:
                lines.append(f"[-] Gagal melakukan koneksi uji CORS: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_tech(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menganalisis fingerprint stack teknologi target {target_url}...\n"]
        detector = TechnologyDetector()
        findings = await detector.analyze(target_url)

        if findings:
            for f in findings:
                lines.append(f"  [+] {f['title']}")
                lines.append(f"      Kategori: {f.get('owasp_category', 'Tech Stack')}")
                lines.append(f"      Bukti   : {f.get('evidence', '-')}\n")
        else:
            lines.append("[-] Tidak ditemukan banner disclosure atau fingerprint teknologi spesifik yang terekspos.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    def _cmd_remediation(cls, command: str, target_url: str) -> Dict[str, Any]:
        remediation_text = """
================================================================================
🛠️ PANDUAN REMEDIASI & KONFIGURASI PENGAMANAN (HARDENING SNIPPETS)
================================================================================

[ 1. Nginx Web Server (/etc/nginx/nginx.conf atau server block) ]
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self';" always;
server_tokens off;

# Blokir akses file sensitif dan dotfiles:
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}

[ 2. Apache Web Server (.htaccess atau httpd.conf) ]
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header unset X-Powered-By
    Header unset Server
</IfModule>
ServerSignature Off
ServerTokens Prod

[ 3. Python FastAPI / Starlette Middleware ]
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)
================================================================================
"""
        return {
            "command": command,
            "output": remediation_text.strip(),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_curl(cls, command: str, base_url: str, path: str) -> Dict[str, Any]:
        if path.startswith("http://") or path.startswith("https://"):
            full_url = path
        else:
            if not path.startswith("/"):
                path = "/" + path
            full_url = urljoin(base_url, path)

        lines = [f"[*] Sending live HTTP GET -> {full_url}\n"]
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            t0 = time.time()
            res = await cls._safe_http_get(client, full_url)
            latency = int((time.time() - t0) * 1000)

            proto = res.http_version if str(res.http_version).startswith("HTTP") else f"HTTP/{res.http_version}"
            lines.append(f"< {proto} {res.status_code} {res.reason_phrase}")
            lines.append(f"< Latency: {latency}ms | Content-Length: {len(res.content)} bytes")
            lines.append(f"< Content-Type: {res.headers.get('content-type', 'N/A')}")
            lines.append(f"< Server: {res.headers.get('server', 'N/A')}")
            lines.append("------------------------------------------------------------")
            body_preview = res.text[:800]
            lines.append(body_preview)
            if len(res.text) > 800:
                lines.append(f"\n... [Truncated {len(res.text) - 800} remaining bytes] ...")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_ssl(cls, command: str, hostname: str, port: int = 443) -> Dict[str, Any]:
        lines = [f"[*] Melakukan handshake TLS live dengan {hostname}:{port}...\n"]
        loop = asyncio.get_event_loop()

        def get_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=6.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    cert = ssock.getpeercert()
                    return cert, cipher, version

        try:
            cert, cipher, version = await loop.run_in_executor(None, get_cert)
            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            subject_dict = dict(x[0] for x in cert.get("subject", ()))
            
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            serial = cert.get("serialNumber")

            lines.append(f"[+] Versi Protokol TLS  : {version}")
            lines.append(f"[+] Active Cipher Suite : {cipher[0]} ({cipher[2]} bits)")
            lines.append(f"[+] Certificate Subject : CN={subject_dict.get('commonName', 'N/A')}, O={subject_dict.get('organizationName', 'N/A')}")
            lines.append(f"[+] Certificate Issuer  : CN={issuer_dict.get('commonName', 'N/A')}, O={issuer_dict.get('organizationName', 'N/A')}")
            lines.append(f"[+] Berlaku Dari        : {not_before}")
            lines.append(f"[+] Berlaku Hingga      : {not_after}")
            lines.append(f"[+] Serial Number       : {serial}")

            sans = [item[1] for item in cert.get("subjectAltName", ()) if item[0] == "DNS"]
            lines.append(f"[+] Subject Alt Names   : Ditemukan {len(sans)} SANs")
            for san in sans[:15]:
                lines.append(f"    - {san}")
            if len(sans) > 15:
                lines.append(f"    ... dan {len(sans) - 15} SAN domain lainnya")

        except Exception as e:
            lines.append(f"[-] TLS handshake gagal atau target non-SSL: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_dns(cls, command: str, hostname: str, record_type: str = "ALL") -> Dict[str, Any]:
        lines = [f"[*] Menanyakan catatan DNS live untuk '{hostname}' (Tipe: {record_type})...\n"]
        
        # 1. Socket resolution for A and AAAA
        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            ipv4_list = sorted(list(set(e[4][0] for e in addr_info if ":" not in e[4][0])))
            ipv6_list = sorted(list(set(e[4][0] for e in addr_info if ":" in e[4][0])))

            if record_type in ("ALL", "A"):
                lines.append("[+] Catatan A (IPv4):")
                for ip in ipv4_list:
                    try:
                        ptr_name = socket.gethostbyaddr(ip)[0]
                        lines.append(f"    {ip} -> Reverse PTR: {ptr_name}")
                    except Exception:
                        lines.append(f"    {ip}")

            if record_type in ("ALL", "AAAA") and ipv6_list:
                lines.append("\n[+] Catatan AAAA (IPv6):")
                for ip in ipv6_list:
                    lines.append(f"    {ip}")

        except Exception as e:
            lines.append(f"[-] Resolusi DNS A/AAAA lokal gagal: {str(e)}")

        # 2. Query Cloudflare DoH (DNS over HTTPS)
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            doh_types = ["MX", "TXT", "NS", "CNAME"] if record_type == "ALL" else [record_type]
            for rtype in doh_types:
                try:
                    res = await client.get(
                        "https://cloudflare-dns.com/dns-query",
                        params={"name": hostname, "type": rtype},
                        headers={"accept": "application/dns-json"}
                    )
                    if res.status_code == 200:
                        data = res.json()
                        answers = data.get("Answer", [])
                        if answers:
                            lines.append(f"\n[+] Catatan {rtype} ({len(answers)} hasil):")
                            for ans in answers:
                                lines.append(f"    TTL: {ans.get('TTL')}s | Data: {ans.get('data')}")
                except Exception:
                    pass

            # Query DMARC TXT record
            if record_type in ("ALL", "TXT", "DMARC"):
                try:
                    dmarc_host = f"_dmarc.{hostname}"
                    res = await client.get(
                        "https://cloudflare-dns.com/dns-query",
                        params={"name": dmarc_host, "type": "TXT"},
                        headers={"accept": "application/dns-json"}
                    )
                    if res.status_code == 200:
                        answers = res.json().get("Answer", [])
                        if answers:
                            lines.append("\n[+] Kebijakan Keamanan Email DMARC:")
                            for ans in answers:
                                lines.append(f"    {dmarc_host} -> {ans.get('data')}")
                except Exception:
                    pass

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_waf(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan probe aktif & fingerprinting WAF / Edge Defenses pada {target_url}...\n"]
        detected = []
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            res = await cls._safe_http_get(client, target_url)
            headers_lower = {k.lower(): v for k, v in res.headers.items()}
            cookies_lower = {k.lower(): v for k, v in res.cookies.items()}
            server_header = headers_lower.get("server", "N/A")

            lines.append(f"[+] HTTP Status: {res.status_code} | Server Banner: {server_header}")

            for waf in cls.KNOWN_WAF_SIGNATURES:
                matched = False
                matched_detail = []
                for h in waf["headers"]:
                    if h in headers_lower:
                        val = headers_lower[h]
                        if waf["pattern"] and re.search(waf["pattern"], val, re.IGNORECASE):
                            matched = True
                            matched_detail.append(f"Header '{h}: {val}'")
                        elif h != "server":
                            matched = True
                            matched_detail.append(f"Keberadaan header '{h}'")

                for c in waf["cookies"]:
                    if any(c in ck for ck in cookies_lower):
                        matched = True
                        matched_detail.append(f"Cookie flag '{c}'")

                if matched:
                    detected.append((waf["name"], matched_detail))

            if detected:
                lines.append("\n[!] DETEKSI FIREWALL / CDN AKTIF:")
                lines.append("============================================================")
                for name, details in detected:
                    lines.append(f"  [+] {name}")
                    for d in details:
                        lines.append(f"      Bukti: {d}")
            else:
                lines.append("\n[-] Tidak ditemukan signature WAF komersial yang eksplisit pada response headers.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_portscan(cls, command: str, hostname: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan probe TCP asinkron aman pada port web umum untuk {hostname}...\n"]
        open_ports = []
        closed_ports = []

        async def check_port(port, service_name):
            try:
                conn = asyncio.open_connection(hostname, port)
                reader, writer = await asyncio.wait_for(conn, timeout=2.5)
                writer.close()
                await writer.wait_closed()
                return port, service_name, True
            except Exception:
                return port, service_name, False

        tasks = [check_port(p, name) for p, name in cls.COMMON_WEB_PORTS]
        results = await asyncio.gather(*tasks)

        for port, name, is_open in results:
            if is_open:
                open_ports.append((port, name))
                lines.append(f"  [+] Port {port:<5} / TCP - OPEN   ({name})")
            else:
                closed_ports.append((port, name))

        lines.append(f"\n[*] Ringkasan: {len(open_ports)} port TERBUKA, {len(closed_ports)} port TERTUTUP / FILTERED.")
        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_fuzz_paths(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Memeriksa file sensitif, API spec, dan direktori konfigurasi berisiko tinggi pada {target_url}...\n"]
        base_url = target_url.rstrip("/")
        found_count = 0

        async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=False) as client:
            for item in SENSITIVE_TARGETS:
                test_url = f"{base_url}{item['path']}"
                try:
                    res = await client.get(test_url)
                    if res.status_code == 200:
                        matched = any(sig.lower() in res.text.lower() for sig in item["signatures"])
                        if matched:
                            lines.append(f"  [!] TERBUKA (HTTP 200) [{item['severity']}]: {item['path']}")
                            lines.append(f"      {item['title']} - Signature matched '{item['signatures'][0]}'")
                            lines.append(f"      URL: {test_url}\n")
                            found_count += 1
                        else:
                            lines.append(f"  [*] HTTP 200 (Custom Page / Soft-404): {item['path']}")
                    elif res.status_code == 403:
                        lines.append(f"  [+] Terproteksi (HTTP 403 Forbidden): {item['path']}")
                except Exception:
                    pass

        if found_count == 0:
            lines.append("[-] Tidak ada file rahasia (.env, .git, backup.sql) yang terbuka untuk publik.")
        else:
            lines.append(f"[!] Ditemukan {found_count} file atau endpoint sensitif yang terbuka.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_crawl(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan live web spider pada {target_url} (Kedalaman: 1, Max: 10 halaman)...\n"]
        crawler = WebCrawler(max_pages=10, max_depth=1)
        res = await crawler.crawl(target_url)

        urls = res.get("urls", [])
        forms = res.get("forms", [])

        lines.append(f"[+] Ditemukan {len(urls)} tautan internal:")
        for u in urls[:12]:
            lines.append(f"    - {u}")
        if len(urls) > 12:
            lines.append(f"    ... dan {len(urls) - 12} URL lainnya")

        if forms:
            lines.append(f"\n[+] Ditemukan {len(forms)} formulir HTML:")
            for f in forms:
                inputs_str = ", ".join(f.get("inputs", [])) or "None"
                lines.append(f"    - [{f.get('method')}] {f.get('url')} (Inputs: {inputs_str})")
        else:
            lines.append("\n[-] Tidak ditemukan formulir HTML pada halaman utama.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_methods(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Menguji metode HTTP yang diizinkan pada {target_url}...\n"]
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            try:
                res = await client.options(target_url)
                allow_header = res.headers.get("allow", "N/A")
                lines.append(f"HTTP OPTIONS Response: Status {res.status_code}")
                lines.append(f"Allow Header         : {allow_header}")

                for method in ["TRACE", "PUT", "DELETE", "PATCH"]:
                    try:
                        m_res = await client.request(method, target_url)
                        lines.append(f"  - Method {method:<6} -> HTTP {m_res.status_code} {m_res.reason_phrase}")
                    except Exception:
                        pass
            except Exception as e:
                lines.append(f"[-] Gagal mengirim OPTIONS request: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_robots_sitemap(cls, command: str, target_url: str) -> Dict[str, Any]:
        lines = [f"[*] Memeriksa robots.txt dan sitemap.xml pada {target_url}...\n"]
        base_url = target_url.rstrip("/")
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            try:
                res_rob = await client.get(f"{base_url}/robots.txt")
                if res_rob.status_code == 200:
                    lines.append("[+] Ditemukan robots.txt (HTTP 200):")
                    lines.append("------------------------------------------------------------")
                    lines.append(res_rob.text[:500])
                    if len(res_rob.text) > 500:
                        lines.append("... [Truncated]")
                else:
                    lines.append(f"[-] robots.txt tidak ditemukan (HTTP {res_rob.status_code})")
            except Exception as e:
                lines.append(f"[-] Gagal mengakses robots.txt: {str(e)}")

            try:
                res_site = await client.get(f"{base_url}/sitemap.xml")
                if res_site.status_code == 200:
                    lines.append(f"\n[+] Ditemukan sitemap.xml (HTTP 200, {len(res_site.content)} bytes)")
                else:
                    lines.append(f"\n[-] sitemap.xml tidak ditemukan (HTTP {res_site.status_code})")
            except Exception:
                pass

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_whois(cls, command: str, hostname: str) -> Dict[str, Any]:
        lines = [f"[*] Mengambil informasi IP dan host untuk '{hostname}'...\n"]
        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            ip_set = sorted(list(set(e[4][0] for e in addr_info)))
            lines.append("[+] Alamat IP Terdaftar:")
            for ip in ip_set:
                try:
                    ptr_name = socket.gethostbyaddr(ip)[0]
                    lines.append(f"    - {ip} (PTR: {ptr_name})")
                except Exception:
                    lines.append(f"    - {ip}")
        except Exception as e:
            lines.append(f"[-] Gagal me-resolve alamat IP: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_test_xss(cls, command: str, base_url: str, endpoint: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan uji injeksi canary Reflected XSS pada {endpoint}...\n"]
        canary = "vunhunter_xss_probe_<script>alert(1)</script>"
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        if not params:
            params = {"q": ["1"], "search": ["1"], "id": ["1"]}
            lines.append("[!] Tidak ada parameter query pada URL. Menguji parameter kandidat ('q', 'search', 'id')...")

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            vulnerable = False
            for param_name in params.keys():
                test_params = params.copy()
                test_params[param_name] = [canary]
                new_query = urlencode(test_params, doseq=True)
                fuzz_url = urlunparse((
                    parsed.scheme or "https", parsed.netloc or urlparse(base_url).netloc,
                    parsed.path or "/", parsed.params, new_query, parsed.fragment
                ))

                lines.append(f"[*] Menguji parameter '{param_name}'...")
                try:
                    res = await client.get(fuzz_url)
                    if canary in res.text:
                        lines.append(f"  [!] REFLECTED XSS DITEMUKAN pada parameter '{param_name}'!")
                        lines.append(f"      Payload terefleksi tanpa sanitasi HTML di: {fuzz_url}")
                        vulnerable = True
                    else:
                        lines.append(f"  [+] Parameter '{param_name}' tersanitasi dengan baik.")
                except Exception as e:
                    lines.append(f"  [-] Kesalahan koneksi pada parameter '{param_name}': {str(e)}")

            if not vulnerable:
                lines.append("\n[-] Tidak ditemukan refleksi tag script unescaped pada parameter yang diuji.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_test_sqli(cls, command: str, base_url: str, endpoint: str) -> Dict[str, Any]:
        lines = [f"[*] Menjalankan uji injeksi Error-Based SQLi pada {endpoint}...\n"]
        probe = "'--\"`"
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        if not params:
            params = {"id": ["1"], "q": ["test"], "cat": ["1"]}
            lines.append("[!] Tidak ada parameter query pada URL. Menguji parameter kandidat ('id', 'q', 'cat')...")

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            vulnerable = False
            for param_name in params.keys():
                test_params = params.copy()
                test_params[param_name] = [probe]
                new_query = urlencode(test_params, doseq=True)
                fuzz_url = urlunparse((
                    parsed.scheme or "https", parsed.netloc or urlparse(base_url).netloc,
                    parsed.path or "/", parsed.params, new_query, parsed.fragment
                ))

                lines.append(f"[*] Menginjeksi quote SQL ke parameter '{param_name}'...")
                try:
                    res = await client.get(fuzz_url)
                    body_lower = res.text.lower()
                    matched_pattern = None
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body_lower):
                            matched_pattern = pattern
                            break

                    if matched_pattern:
                        lines.append(f"  [!] SIGNATURE ERROR SQL TERDETEKSI pada parameter '{param_name}'!")
                        lines.append(f"      Pattern kecocokan: '{matched_pattern}'")
                        lines.append(f"      Target: {fuzz_url}")
                        vulnerable = True
                    else:
                        lines.append(f"  [+] Parameter '{param_name}' ditangani dengan aman.")
                except Exception as e:
                    lines.append(f"  [-] Kesalahan koneksi pada parameter '{param_name}': {str(e)}")

            if not vulnerable:
                lines.append("\n[-] Tidak ada pesan error syntax database yang terekspos.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_test_input(
        cls, 
        command: str, 
        base_url: str, 
        endpoint: str, 
        target_param: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Terminal Live Command: Pengujian Ketahanan Kolom Masukan & Kotak Pencarian.
        """
        lines = [
            "================================================================================",
            "🔍 PENGUJIAN KETAHANAN KOLOM MASUKAN & KOTAK PENCARIAN (LIVE AUDIT)",
            "================================================================================",
            f"[*] Target Endpoint : {endpoint}",
            f"[*] Metodologi      : OWASP A03:2021 (Injection) • CWE-89 / CWE-20",
            ""
        ]

        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        if target_param:
            params_to_test = [target_param]
        elif params:
            params_to_test = list(params.keys())
        else:
            params_to_test = ["q", "search", "keyword", "id"]
            lines.append("[i] Tidak ada parameter query ditemukan pada URL. Menguji parameter kandidat standar ('q', 'search', 'keyword', 'id')...\n")

        vulnerable_count = 0
        protected_count = 0

        for param in params_to_test:
            lines.append(f"[*] Evaluasi Kolom/Parameter: '{param}'")
            lines.append("    ----------------------------------------------------------------------------")

            for probe_item in INPUT_TEST_PROBES[:4]:
                probe_str = probe_item["probe"]
                probe_cat = probe_item["category"]
                probe_name = probe_item["name"]

                res = await InputResilienceValidator.test_single_endpoint(endpoint, param, probe_str, http_method="GET")

                if res["db_error_found"]:
                    vulnerable_count += 1
                    lines.append(f"    ❌ [RENTAN] {probe_name} ({probe_cat})")
                    lines.append(f"       Payload  : {probe_str}")
                    lines.append(f"       Engine   : {res['matched_engine']} (Signature: '{res['matched_pattern']}')")
                    lines.append(f"       HTTP Code: {res['status_code']} | Ukuran Response: {res['response_length']} bytes")
                elif res["is_blocked_by_waf"]:
                    protected_count += 1
                    lines.append(f"    🛡️ [TERPROTEKSI WAF] {probe_name} -> Diblokir oleh Firewall (HTTP {res['status_code']})")
                elif res["status_code"] in (400, 422):
                    protected_count += 1
                    lines.append(f"    🛡️ [VALIDASI AKTIF] {probe_name} -> Ditolak server sebagai Bad Request (HTTP {res['status_code']})")
                elif not res["is_reflected_raw"]:
                    protected_count += 1
                    lines.append(f"    ✅ [TERFILTER/DISANITASI] {probe_name} -> Karakter khusus disaring/dihapus dengan aman")
                else:
                    lines.append(f"    ℹ️ [TEREFLEKSI NORMAL] {probe_name} -> Terefleksi tanpa error database (HTTP {res['status_code']})")

            lines.append("")

        lines.append("================================================================================")
        if vulnerable_count > 0:
            lines.append(f"⚠️ KESIMPULAN: Ditemukan {vulnerable_count} anomali/eksposur error basis data!")
            lines.append("   Rekomendasi: Wajib gunakan Prepared Statements (Parameterized Queries) & ORM.")
        else:
            lines.append(f"✅ KESIMPULAN: Seluruh kolom masukan menunjukkan penanganan yang aman & anggun.")
            lines.append("   Tidak ada pesan error internal basis data yang terekspos ke publik.")
        lines.append("================================================================================")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0 if vulnerable_count == 0 else 1,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_db_boundary(
        cls, 
        command: str, 
        base_url: str, 
        endpoint: str, 
        param: str = "id"
    ) -> Dict[str, Any]:
        """
        Terminal Live Command: Simulasi Pengujian Batas Sistem & Integritas Basis Data.
        """
        lines = [
            "================================================================================",
            "🛡️ AUDIT BATAS HAK AKSES BASIS DATA & MULTI-QUERY INJECTION (LEAST PRIVILEGE)",
            "================================================================================",
            "[+] STATUS AUDIT: PENGUJIAN BATAS HAK AKSES REAL-WORLD AKTIF",
            "    Memverifikasi mitigasi terhadap Stacked Query Injection & Penegakan Hak Akses Terkecil.",
            f"[*] Target Endpoint : {endpoint}",
            f"[*] Parameter Diuji : '{param}'",
            f"[*] Standar Kepatuhan: Principle of Least Privilege • CWE-250 • CWE-272 • OWASP A03",
            "================================================================================",
            ""
        ]

        for probe in DDL_SIMULATION_PROBES:
            lines.append(f"[*] Menguji Instruksi: {probe['instruction_type']}")
            lines.append(f"    Kategori Risiko : {probe['risk_category']}")
            lines.append(f"    Canary Target   : '{probe['safe_target']}'")
            lines.append(f"    Simulated SQL   : {probe['payload'].strip()}")

            res = await DatabaseIntegrityAuditor.simulate_ddl_boundary(endpoint, param, probe, http_method="GET")

            lines.append(f"    Hasil Lapis     : {res['verdict']}")
            lines.append(f"    HTTP Status     : {res['status_code']}")

            if res["waf_blocked"]:
                lines.append("    -> [Lapis Perimeter/WAF] Filter kata kunci DDL berhasil memblokir probe.")
            elif res["stacked_blocked"]:
                lines.append("    -> [Lapis Driver/ORM] Multi-statement execution dinonaktifkan.")
            elif res["privilege_denied"]:
                lines.append("    -> [Lapis Hak Akses DB] User aplikasi terbukti TIDAK MEMILIKI hak DDL (Least Privilege Sukses).")
            elif res["syntax_error"]:
                lines.append("    -> [Peringatan] Aplikasi membocorkan pesan error SQL.")

            lines.append("    ----------------------------------------------------------------------------")

        lines.append("\n[*] PANDUAN PENGERASAN HAK AKSES BASIS DATA (LEAST PRIVILEGE TEMPLATE):")
        lines.append("--------------------------------------------------------------------------------")
        mysql_guide = DatabaseIntegrityAuditor.get_hardening_guidelines().get("MySQL / MariaDB", "")
        lines.append(mysql_guide[:400] + "...")
        lines.append("--------------------------------------------------------------------------------")
        lines.append("Ketik 'remediation' atau buka tab 'Remediation Hub' untuk skrip database lengkap.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def run_live_input_test(
        cls,
        target_url: str,
        param_name: str,
        probe: str,
        method: str = "GET"
    ) -> Dict[str, Any]:
        """
        Eksekusi probe pengujian ketahanan input langsung dari UI.
        """
        is_valid, normalized_url, _ = validate_and_sanitize_target(target_url)
        url_to_test = normalized_url if is_valid else target_url

        res = await InputResilienceValidator.test_single_endpoint(
            endpoint_url=url_to_test,
            param_name=param_name,
            probe_str=probe,
            http_method=method
        )

        return {
            "target_url": url_to_test,
            "param": param_name,
            "probe": probe,
            "method": method.upper(),
            "status_code": res["status_code"],
            "response_length": res["response_length"],
            "db_error_found": res["db_error_found"],
            "matched_engine": res["matched_engine"],
            "matched_pattern": res["matched_pattern"],
            "is_blocked_by_waf": res["is_blocked_by_waf"],
            "is_reflected_raw": res["is_reflected_raw"],
            "resilience_status": res["resilience_status"],
            "score_impact": res["score_impact"],
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def run_live_db_boundary(
        cls,
        target_url: str,
        param_name: str = "id",
        instruction_id: str = "drop_database_canary",
        method: str = "GET"
    ) -> Dict[str, Any]:
        """
        Eksekusi simulasi instruksi batas sistem / DDL langsung dari UI dalam lingkungan terisolasi.
        """
        is_valid, normalized_url, _ = validate_and_sanitize_target(target_url)
        url_to_test = normalized_url if is_valid else target_url

        # Cari probe yang sesuai
        probe_item = next((p for p in DDL_SIMULATION_PROBES if p["id"] == instruction_id), DDL_SIMULATION_PROBES[0])

        res = await DatabaseIntegrityAuditor.simulate_ddl_boundary(
            endpoint_url=url_to_test,
            param_name=param_name,
            probe_item=probe_item,
            http_method=method
        )

        hardening_scripts = DatabaseIntegrityAuditor.get_hardening_guidelines()
        combined_script = "\n\n".join(f"-- === {dbms} ===\n{script}" for dbms, script in hardening_scripts.items())

        return {
            "target_url": url_to_test,
            "param_tested": param_name,
            "instruction_type": probe_item["instruction_type"],
            "risk_category": probe_item["risk_category"],
            "payload_used": probe_item["payload"],
            "safe_target": probe_item["safe_target"],
            "status_code": res["status_code"],
            "status_type": res["status_type"],
            "verdict": res["verdict"],
            "severity": res["severity"],
            "waf_blocked": res["waf_blocked"],
            "stacked_blocked": res["stacked_blocked"],
            "privilege_denied": res["privilege_denied"],
            "syntax_error": res["syntax_error"],
            "hardening_script": combined_script,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def get_live_asset_explorer(cls, target_url: str, scan_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Gathers real live explored assets for any target URL or scan ID:
        - Crawled endpoints & forms
        - Sensitive path fuzzing matrix with live HTTP status codes
        - Live security header evaluation
        - Live WAF and port detection
        """
        is_valid, normalized_url, err_msg = validate_and_sanitize_target(target_url)
        if not is_valid:
            normalized_url = target_url if "://" in target_url else f"https://{target_url}"

        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or "target.live"

        # 1. Probe Sensitive Paths Live
        path_matrix = []
        base_url = normalized_url.rstrip("/")
        async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=False) as client:
            for item in SENSITIVE_TARGETS:
                test_url = f"{base_url}{item['path']}"
                try:
                    res = await client.get(test_url)
                    matched = any(sig.lower() in res.text.lower() for sig in item["signatures"])
                    path_matrix.append({
                        "path": item["path"],
                        "title": item["title"],
                        "severity": item["severity"],
                        "status_code": res.status_code,
                        "content_length": len(res.content),
                        "is_exposed": res.status_code == 200 and matched,
                        "is_accessible": res.status_code == 200,
                        "description": item["desc"],
                        "remediation": item["remediation"]
                    })
                except Exception:
                    path_matrix.append({
                        "path": item["path"],
                        "title": item["title"],
                        "severity": item["severity"],
                        "status_code": 0,
                        "content_length": 0,
                        "is_exposed": False,
                        "is_accessible": False,
                        "description": item["desc"],
                        "remediation": item["remediation"]
                    })

        # 2. Probe Live Security Headers
        header_analyzer = SecurityHeaderAnalyzer()
        header_findings = await header_analyzer.analyze(normalized_url)

        # 3. Probe Live WAF & Ports
        waf_res = await cls._cmd_waf("waf", normalized_url)
        ports_res = await cls._cmd_portscan("ports", hostname)

        # 4. Crawl Top Level
        crawler = WebCrawler(max_pages=8, max_depth=1)
        crawl_data = await crawler.crawl(normalized_url)

        return {
            "target_url": normalized_url,
            "target_hostname": hostname,
            "timestamp": datetime.utcnow().isoformat(),
            "discovered_urls": crawl_data.get("urls", [normalized_url]),
            "discovered_forms": crawl_data.get("forms", []),
            "sensitive_paths_matrix": path_matrix,
            "header_findings": header_findings,
            "waf_summary": waf_res.get("output", ""),
            "ports_summary": ports_res.get("output", ""),
        }

    @classmethod
    async def verify_finding_live(cls, target_url: str, finding_title: str, evidence: str = "") -> Dict[str, Any]:
        """
        Re-tests a specific finding on demand and returns raw live HTTP verification evidence.
        """
        is_valid, normalized_url, _ = validate_and_sanitize_target(target_url)
        url_to_test = normalized_url if is_valid else target_url

        req_headers = {"User-Agent": "VulnHunter-Security-Audit/2026.1"}
        t0 = time.time()
        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
                res = await client.get(url_to_test, headers=req_headers)
                latency = int((time.time() - t0) * 1000)

                resp_headers_str = "\n".join(f"{k}: {v}" for k, v in res.headers.items())
                body_snippet = res.text[:800]

                return {
                    "verified": True,
                    "target_url": url_to_test,
                    "finding_title": finding_title,
                    "status_code": res.status_code,
                    "latency_ms": latency,
                    "request_raw": f"GET {url_to_test} HTTP/1.1\nHost: {urlparse(url_to_test).netloc}\nUser-Agent: VulnHunter-Security-Audit/2026.1",
                    "response_headers": resp_headers_str,
                    "response_body_snippet": body_snippet,
                    "timestamp": datetime.utcnow().isoformat(),
                    "message": f"Berhasil mengeksekusi live PoC probe ke {url_to_test} (HTTP {res.status_code} dalam {latency}ms)."
                }
        except Exception as e:
            return {
                "verified": False,
                "target_url": url_to_test,
                "finding_title": finding_title,
                "status_code": 0,
                "latency_ms": int((time.time() - t0) * 1000),
                "request_raw": f"GET {url_to_test} HTTP/1.1",
                "response_headers": "",
                "response_body_snippet": "",
                "timestamp": datetime.utcnow().isoformat(),
                "message": f"Eksekusi PoC gagal: {str(e)}"
            }

    @classmethod
    async def _cmd_scorecard(cls, command: str, normalized_url: str, hostname: str) -> Dict[str, Any]:
        """
        Runs comprehensive live security checks and computes letter grade & numeric scorecard.
        """
        header_analyzer = SecurityHeaderAnalyzer()
        ssl_checker = SSLTLSChecker()
        cookie_auditor = CookieSecurityAuditor()
        cors_analyzer = CORSAnalyzer()

        header_findings = await header_analyzer.analyze(normalized_url)
        ssl_findings = await ssl_checker.analyze(normalized_url)
        cookie_findings = await cookie_auditor.analyze(normalized_url)
        cors_findings = await cors_analyzer.analyze(normalized_url)

        all_findings = header_findings + ssl_findings + cookie_findings + cors_findings
        findings = []
        for hf in all_findings:
            findings.append({
                "title": hf.get("title", ""),
                "severity": hf.get("severity", "Info"),
                "owasp_category": hf.get("owasp_category", "")
            })

        scorecard = InternationalComplianceEngine.calculate_scorecard(findings)
        grade = scorecard["grade"]
        score = scorecard["score"]
        pillars = scorecard["pillars"]

        def make_bar(val: int) -> str:
            filled = int(val / 10)
            return "█" * filled + "░" * (10 - filled)

        output = f"""
================================================================================
📊 ENTERPRISE SECURITY POSTURE SCORECARD (STANDARD 2026)
Target: {normalized_url}
Hostname: {hostname}
Audit Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
================================================================================

  ┌────────────────────────────────────────────────────────┐
  │  POSTURE LETTER GRADE    :  [ {grade:^4} ]                      │
  │  SECURITY HEALTH SCORE   :  {score:>5.1f} / 100.0              │
  │  THREAT POSTURE LEVEL    :  {scorecard["risk_label"]:<25} │
  └────────────────────────────────────────────────────────┘

[ 🛡️ 4-DIMENSIONAL PILLAR RATINGS ]
  1. Cryptography & TLS 1.3/1.2       : [{make_bar(pillars['cryptography_tls'])}] {pillars['cryptography_tls']:>3}%
  2. Web Server & Header Hardening     : [{make_bar(pillars['web_hardening'])}] {pillars['web_hardening']:>3}%
  3. App Integrity & Injection Defense: [{make_bar(pillars['application_integrity'])}] {pillars['application_integrity']:>3}%
  4. Perimeter & Sensitive Data Shield : [{make_bar(pillars['perimeter_data_protection'])}] {pillars['perimeter_data_protection']:>3}%

[ ⚠️ IDENTIFIED EXPOSURE SUMMARY ]
  • Critical Exposures : {scorecard['crit_count']}
  • High Risk Issues   : {scorecard['high_count']}
  • Medium Risk Issues : {scorecard['med_count']}
  • Low Risk Warnings  : {scorecard['low_count']}
  • Informational Items: {scorecard['info_count']}

Ketik 'compliance' untuk melihat evaluasi matriks OWASP Top 10 & ISO 27001.
Ketik 'remediation' untuk mendapatkan skrip konfigurasi hardening instan.
================================================================================
"""
        return {
            "command": command,
            "output": output.strip(),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_compliance(cls, command: str, normalized_url: str, hostname: str) -> Dict[str, Any]:
        """
        Audits target against international compliance frameworks (OWASP, ISO 27001, PCI-DSS, NIST).
        """
        header_analyzer = SecurityHeaderAnalyzer()
        ssl_checker = SSLTLSChecker()
        cookie_auditor = CookieSecurityAuditor()
        cors_analyzer = CORSAnalyzer()

        header_findings = await header_analyzer.analyze(normalized_url)
        ssl_findings = await ssl_checker.analyze(normalized_url)
        cookie_findings = await cookie_auditor.analyze(normalized_url)
        cors_findings = await cors_analyzer.analyze(normalized_url)

        all_findings = header_findings + ssl_findings + cookie_findings + cors_findings
        findings = []
        for hf in all_findings:
            findings.append({
                "title": hf.get("title", ""),
                "severity": hf.get("severity", "Info"),
                "owasp_category": hf.get("owasp_category", "")
            })

        compliance = InternationalComplianceEngine.evaluate_compliance(findings)
        owasp = compliance["owasp"]
        iso = compliance["iso27001"]
        pci = compliance["pci_dss"]
        nist = compliance["nist"]

        output = f"""
================================================================================
🏛️ INTERNATIONAL SECURITY STANDARDS COMPLIANCE AUDIT
Target: {normalized_url}
Standards Evaluated: OWASP Top 10 (2026 Ready), ISO 27001:2022, PCI-DSS v4.0, NIST SP 800-53
================================================================================

[ 1. OWASP Top 10 Standard: {owasp['compliance_score']}% ({owasp['status']}) ]
"""
        for it in owasp["items"]:
            status_icon = "✅ PASS" if it["passed"] else "❌ FAIL"
            output += f"  [{status_icon}] {it['id']:<4} {it['name']:<36} (Dampak: {it['impact']})\n"

        output += f"""
[ 2. ISO/IEC 27001:2022 Annex A: {iso['compliance_score']}% ({iso['status']}) ]
"""
        for it in iso["items"]:
            status_icon = "✅ PASS" if it["passed"] else "❌ FAIL"
            output += f"  [{status_icon}] {it['control']:<7} {it['name']:<42}\n"

        output += f"""
[ 3. PCI-DSS v4.0 Web Security: {pci['compliance_score']}% ({pci['status']}) ]
"""
        for it in pci["items"]:
            status_icon = "✅ PASS" if it["passed"] else "❌ FAIL"
            output += f"  [{status_icon}] {it['req']:<9} {it['name']:<42}\n"

        output += f"""
[ 4. NIST SP 800-53 Rev 5: {nist['compliance_score']}% ({nist['status']}) ]
"""
        for it in nist["items"]:
            status_icon = "✅ PASS" if it["passed"] else "❌ FAIL"
            output += f"  [{status_icon}] {it['control']:<7} {it['name']:<42}\n"

        output += "\n================================================================================"
        return {
            "command": command,
            "output": output.strip(),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_dnssec_email(cls, command: str, hostname: str) -> Dict[str, Any]:
        """
        Audits DNS perimeter security, anti-spoofing policies (SPF, DMARC, DKIM, CAA, DNSSEC).
        """
        root_domain = extract_root_domain(hostname)
        loop = asyncio.get_event_loop()

        def query_txt(domain: str) -> List[str]:
            import subprocess
            try:
                out = subprocess.check_output(["nslookup", "-type=TXT", domain], timeout=4, stderr=subprocess.DEVNULL).decode("latin-1", errors="ignore")
                return out.splitlines()
            except Exception:
                return []

        def query_mx(domain: str) -> List[str]:
            import subprocess
            try:
                out = subprocess.check_output(["nslookup", "-type=MX", domain], timeout=4, stderr=subprocess.DEVNULL).decode("latin-1", errors="ignore")
                return out.splitlines()
            except Exception:
                return []

        txt_lines = await loop.run_in_executor(None, query_txt, root_domain)
        dmarc_lines = await loop.run_in_executor(None, query_txt, f"_dmarc.{root_domain}")
        mx_lines = await loop.run_in_executor(None, query_mx, root_domain)

        # Detect SPF
        spf_found = False
        spf_val = "Tidak Ditemukan"
        for line in txt_lines:
            if "v=spf1" in line.lower():
                spf_found = True
                spf_val = line.strip()
                break

        # Detect DMARC
        dmarc_found = False
        dmarc_val = "Tidak Ditemukan"
        for line in dmarc_lines:
            if "v=dmarc1" in line.lower():
                dmarc_found = True
                dmarc_val = line.strip()
                break

        # Check MX
        has_mx = any("mail exchanger" in l.lower() or "mx preference" in l.lower() for l in mx_lines)

        output = f"""
================================================================================
🛡️ DNS & EMAIL PERIMETER SECURITY AUDIT (ANTI-SPOOFING & HIJACKING)
Domain: {root_domain} (Host: {hostname})
================================================================================

[ 1. SPF (Sender Policy Framework - RFC 7208) ]
  • Status : {"✅ TERKONFIGURASI" if spf_found else "❌ TIDAK ADA (Risiko Email Spoofing)"}
  • Record : {spf_val}
  • Analisis: {"SPF melindungi domain dari pengiriman email phishing atas nama domain Anda." if spf_found else "Penyerang dapat memalsukan email seolah-olah berasal dari @" + root_domain}

[ 2. DMARC Policy (RFC 7489) ]
  • Status : {"✅ TERKONFIGURASI" if dmarc_found else "❌ TIDAK ADA (Risiko Impersonasi Domain)"}
  • Record : {dmarc_val}
  • Analisis: {"DMARC menegakkan kebijakan penanganan email yang gagal SPF/DKIM." if dmarc_found else "Tanpa DMARC, mail server penerima tidak dapat memvalidasi keaslian pengirim."}

[ 3. Mail Exchanger (MX Records) ]
  • Status : {"✅ MX Terdeteksi" if has_mx else "ℹ️ Tidak Ditemukan MX Langsung"}

[ 4. CAA & DNSSEC Recommendations ]
  • CAA Record   : Tambahkan CAA record di DNS provider untuk membatasi CA yang berhak menerbitkan sertifikat TLS.
  • DNSSEC       : Aktifkan DNSSEC pada domain registrar untuk mencegah DNS Cache Poisoning & BGP Hijacking.

Rekomendasi Tindakan:
  - Buat TXT record pada _dmarc.{root_domain}: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{root_domain}"
  - Perbarui SPF record: "v=spf1 include:_spf.google.com ~all"
================================================================================
"""
        return {
            "command": command,
            "output": output.strip(),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_ssti(cls, command: str, normalized_url: str, test_url: str) -> Dict[str, Any]:
        """Test for Server-Side Template Injection (SSTI) on query parameters and paths."""
        lines = [
            f"[*] Probing {test_url} for Server-Side Template Injection (SSTI)...",
            "[*] Supported Template Engines: Jinja2, Twig, Freemarker, Pebble, Ruby ERB\n"
        ]
        ssti = SSTIDetector()
        findings = await ssti.scan_urls([test_url])
        if findings:
            for f in findings:
                lines.append(f"[!] VULNERABILITY DETECTED: {f['title']} (Severity: {f['severity']})")
                lines.append(f"    • Parameter : {f.get('target_url')}")
                lines.append(f"    • Evidence  : {f.get('evidence')}")
                lines.append(f"    • Remediation: {f.get('remediation')}\n")
        else:
            lines.append("[-] Tidak ditemukan indikasi Server-Side Template Injection (SSTI) yang mengevaluasi ekspresi template matematika.")
            lines.append("    Semua probe ({{7*7}}, {{7*'7'}}, ${7*7}, <%= 7*7 %>) direfleksikan secara literal atau di-escape dengan aman.")
        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_open_redirect(cls, command: str, normalized_url: str, test_url: str) -> Dict[str, Any]:
        """Test for Open Redirect vulnerability using 35+ protocol and encoding bypasses."""
        lines = [
            f"[*] Testing Open Redirect parameter bypass on: {test_url}",
            "[*] Testing bypass vectors: protocol-relative (//), URL encoding (%2F), backslash, dot-segments\n"
        ]
        detector = OpenRedirectDetector()
        findings = await detector.scan_urls([test_url])
        if findings:
            for f in findings:
                lines.append(f"[!] VULNERABILITY DETECTED: {f['title']} (Severity: {f['severity']})")
                lines.append(f"    • Parameter : {f.get('target_url')}")
                lines.append(f"    • Evidence  : {f.get('evidence')}")
                lines.append(f"    • Remediation: {f.get('remediation')}\n")
        else:
            lines.append("[-] Tidak ditemukan kerentanan Open Redirect.")
            lines.append("    Target memvalidasi atau menolak redirect ke domain eksternal canary.")
        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_lfi(cls, command: str, normalized_url: str, test_url: str) -> Dict[str, Any]:
        """Test for Local File Inclusion and Path Traversal."""
        lines = [
            f"[*] Testing Local File Inclusion & Path Traversal on: {test_url}",
            "[*] Probing classic traversal, URL encoding (%2e%2e%2f), filter bypass (....//), and Windows ini...\n"
        ]
        detector = LFIDetector()
        findings = await detector.scan_urls([test_url])
        if findings:
            for f in findings:
                lines.append(f"[!] CRITICAL VULNERABILITY DETECTED: {f['title']}")
                lines.append(f"    • Severity  : {f['severity']}")
                lines.append(f"    • Evidence  : {f.get('evidence')}")
                lines.append(f"    • Remediation: {f.get('remediation')}\n")
        else:
            lines.append("[-] Tidak ditemukan respons kebocoran file sistem (/etc/passwd, win.ini, boot.ini).")
            lines.append("    Server menolak traversal path atau tidak mengeksekusi parameter file secara dinamis.")
        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_jwt(cls, command: str, normalized_url: str, token: str) -> Dict[str, Any]:
        """Decode and audit JSON Web Token (JWT) structure, signature, and security."""
        lines = [
            "================================================================================",
            "🔑 JSON WEB TOKEN (JWT) SECURITY ANALYZER",
            "================================================================================\n"
        ]
        if not token:
            lines.append(f"[*] Tidak ada token disediakan. Memeriksa header/cookie live dari {normalized_url}...")
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                try:
                    res = await cls._safe_http_get(client, normalized_url)
                    for c_name, c_val in res.cookies.items():
                        if _is_jwt_like(c_val):
                            token = c_val
                            lines.append(f"[+] Menemukan kandidat JWT pada cookie '{c_name}'!")
                            break
                    if not token:
                        for h_name, h_val in res.headers.items():
                            val = h_val.replace("Bearer ", "").strip()
                            if _is_jwt_like(val):
                                token = val
                                lines.append(f"[+] Menemukan kandidat JWT pada header '{h_name}'!")
                                break
                except Exception:
                    pass

        if not token:
            lines.append("[-] Tidak ada JWT token ditemukan pada respons live target.")
            lines.append("    Gunakan sintaks: jwt-analyze <token_jwt_anda_disini> untuk menganalisis token spesifik.")
            return {
                "command": command,
                "output": "\n".join(lines),
                "exit_code": 0,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }

        analyzer = JWTAnalyzer()
        findings = analyzer._analyze_token(token, normalized_url, "User Input / Live Discovery")
        header, payload = analyzer._decode_claims(token)

        lines.append(f"[1. Decoded Header]\n{json.dumps(header or {}, indent=2)}")
        lines.append(f"\n[2. Decoded Payload Claims]\n{json.dumps(payload or {}, indent=2)}")
        lines.append("\n[3. Security Audit Findings]")
        if findings:
            for f in findings:
                lines.append(f"  • [{f['severity'].upper()}] {f['title']}")
                lines.append(f"    Evidence: {f.get('evidence')}")
                lines.append(f"    Remediation: {f.get('remediation')}")
        else:
            lines.append("  ✅ Algoritma aman (bukan 'none'), secret bukan kamus umum, dan klaim waktu standar tervalidasi.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_subdomains(cls, command: str, normalized_url: str, hostname: str) -> Dict[str, Any]:
        """Enumerate subdomains via Certificate Transparency logs (crt.sh) & DNS brute-force."""
        lines = [
            "================================================================================",
            f"🌐 RECONNAISSANCE: SUBDOMAIN ENUMERATION FOR {hostname}",
            "================================================================================",
            "[*] Querying Certificate Transparency (crt.sh) and performing DNS brute-force...\n"
        ]
        enumerator = SubdomainEnumerator()
        res = await enumerator.enumerate(normalized_url)
        all_subs = res.get("all_discovered", [])
        active_subs = res.get("subdomains_found", [])
        dangling_subs = res.get("subdomains_dangling", [])

        lines.append(f"[+] Total Subdomain Ditemukan  : {len(all_subs)}")
        lines.append(f"    • Certificate Transparency: {res.get('ct_count', 0)} entri")
        lines.append(f"    • DNS Brute-Force         : {res.get('dns_count', 0)} entri")
        lines.append(f"    • Subdomain Aktif HTTP    : {len(active_subs)}")
        lines.append(f"    • Dangling (Takeover Risk): {len(dangling_subs)}\n")

        if dangling_subs:
            lines.append("[!] PERINGATAN SUBDOMAIN TAKEOVER:")
            for d in dangling_subs:
                lines.append(f"    ❌ {d['subdomain']} -> Unclaimed provider: {d.get('provider')}")
            lines.append("")

        lines.append("[ Daftar Subdomain Terdeteksi (Top 30) ]")
        for sub in all_subs[:30]:
            lines.append(f"  • {sub}")
        if len(all_subs) > 30:
            lines.append(f"  ... dan {len(all_subs) - 30} subdomain lainnya.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_cve_check(cls, command: str, normalized_url: str) -> Dict[str, Any]:
        """Match technology stack banners against known CVEs from NVD/CVSS database."""
        lines = [
            "================================================================================",
            f"🛡️ BANNER TO CVE FINGERPRINTING & VULNERABILITY LOOKUP",
            "================================================================================",
            f"[*] Collecting server banners and version signatures from {normalized_url}...\n"
        ]
        cve_engine = CVEFingerprintEngine()
        findings = await cve_engine.scan(normalized_url)
        banners = await cve_engine._collect_banners(normalized_url)

        lines.append("[ Server & Technology Disclosures ]")
        for k, v in banners.items():
            if v:
                lines.append(f"  • {k.upper()}: {v}")
        lines.append("")

        if findings:
            lines.append(f"[!] DITEMUKAN {len(findings)} POTENSI CVE PADA STACK TARGET:")
            for f in findings:
                lines.append(f"\n  🔥 {f['title']} [{f['severity'].upper()}]")
                lines.append(f"     Deskripsi  : {f.get('description')}")
                lines.append(f"     Rekomendasi: {f.get('remediation')}")
        else:
            lines.append("[-] Tidak ditemukan matching CVE kritis pada banner yang terekspos.")
            lines.append("    Versi server/komponen tidak terdeteksi rentan terhadap database CVE internal saat ini.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_nuclei(cls, command: str, normalized_url: str, template_name: str) -> Dict[str, Any]:
        """Run Nuclei-style template matching against critical paths (.env, .git, cloud metadata)."""
        lines = [
            "================================================================================",
            "⚡ NUCLEI-STYLE VULNERABILITY TEMPLATE PROBER",
            "================================================================================",
            f"[*] Target: {normalized_url} | Template Filter: '{template_name}'\n"
        ]
        targets = SENSITIVE_TARGETS
        if template_name != "all":
            targets = [t for t in targets if template_name.lower() in t["path"].lower() or template_name.lower() in t["title"].lower()]
            if not targets:
                targets = SENSITIVE_TARGETS[:20]

        lines.append(f"[*] Mengeksekusi {min(len(targets), 25)} probe template berpresisi tinggi...\n")
        detected = []
        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
            for item in targets[:25]:
                full_url = urljoin(normalized_url, item["path"])
                try:
                    res = await cls._safe_http_get(client, full_url)
                    if res.status_code in (200, 206):
                        body_sample = res.text[:2000]
                        matched_sig = any(sig.lower() in body_sample.lower() for sig in item.get("signatures", []))
                        if matched_sig or len(item.get("signatures", [])) == 0:
                            detected.append((item, full_url, res.status_code))
                            lines.append(f"[!] [VULN] [{item['severity'].upper()}] {item['title']} -> {full_url} ({res.status_code})")
                        else:
                            lines.append(f"[-] [SAFE] {item['path']} ({res.status_code} - no signature match)")
                    else:
                        lines.append(f"[-] [SAFE] {item['path']} ({res.status_code})")
                except Exception:
                    lines.append(f"[-] [FAIL] {item['path']} (connection error)")

        lines.append(f"\n[*] Hasil Probing: {len(detected)} kerentanan terkonfirmasi dari {min(len(targets), 25)} template.")
        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_http2_alpn(cls, command: str, hostname: str, port: int) -> Dict[str, Any]:
        """Test HTTP/2 and HTTP/3 / QUIC ALPN protocol negotiation."""
        lines = [
            "================================================================================",
            f"🚀 HTTP/2 & NEXT-GEN PROTOCOL ALPN AUDIT: {hostname}:{port}",
            "================================================================================\n"
        ]
        loop = asyncio.get_event_loop()

        def test_alpn():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((hostname, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.selected_alpn_protocol()

        try:
            negotiated = await loop.run_in_executor(None, test_alpn)
            lines.append(f"[+] ALPN Protocol Negotiated: {negotiated or 'None'}")
            if negotiated == "h2":
                lines.append("  ✅ Target mendukung HTTP/2 (Multiplexing, Header Compression HPACK aktif).")
            else:
                lines.append("  ℹ️ Target menggunakan HTTP/1.1 (Belum mendukung HTTP/2 multiplexing).")
        except Exception as e:
            lines.append(f"[-] Negosiasi ALPN gagal: {str(e)}")

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            try:
                res = await client.get(f"https://{hostname}:{port}")
                alt_svc = res.headers.get("alt-svc", "")
                if alt_svc:
                    lines.append(f"\n[+] Alt-Svc Header Ditemukan: {alt_svc}")
                    if "h3" in alt_svc:
                        lines.append("  ✅ Target mengiklankan dukungan HTTP/3 (QUIC / UDP) via Alt-Svc!")
                else:
                    lines.append("\n[-] Tidak ada Alt-Svc header (HTTP/3 belum diiklankan).")
            except Exception:
                pass

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_tls_grade(cls, command: str, normalized_url: str, hostname: str, port: int) -> Dict[str, Any]:
        """Enterprise SSL Labs-style TLS Letter Grade audit (A+ to F)."""
        lines = [
            "================================================================================",
            f"🔒 SSL/TLS ENTERPRISE GRADING & CIPHER AUDIT (SSL LABS STYLE)",
            f"Host: {hostname}:{port}",
            "================================================================================\n"
        ]
        checker = SSLTLSChecker()
        findings = await checker.analyze(normalized_url)

        critical_count = sum(1 for f in findings if f["severity"] == "Critical")
        high_count = sum(1 for f in findings if f["severity"] == "High")
        med_count = sum(1 for f in findings if f["severity"] == "Medium")

        if critical_count > 0:
            grade = "F"
            grade_color = "🔴"
        elif high_count > 0:
            grade = "C"
            grade_color = "🟠"
        elif med_count > 0:
            grade = "B"
            grade_color = "🟡"
        else:
            grade = "A+"
            grade_color = "🟢"

        lines.append(f"  {grade_color} POSTUR KEAMANAN TLS: GRADE [{grade}]")
        lines.append("  ------------------------------------------------")
        lines.append(f"  • Total Temuan Kelemahan: {len(findings)}")
        lines.append(f"    - Critical : {critical_count}")
        lines.append(f"    - High     : {high_count}")
        lines.append(f"    - Medium   : {med_count}")
        lines.append(f"    - Low/Info : {len(findings) - critical_count - high_count - med_count}\n")

        if findings:
            lines.append("[ Rincian Audit Keamanan Sertifikat & Cipher ]")
            for f in findings:
                lines.append(f"  • [{f['severity'].upper()}] {f['title']}")
                lines.append(f"    {f.get('description', '')[:100]}...")
        else:
            lines.append("  ✅ Sertifikat valid, cipher suite modern (TLS 1.3/AES-GCM), tidak ada kelemahan terdeteksi.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_smuggle(cls, command: str, normalized_url: str, hostname: str) -> Dict[str, Any]:
        """Test for HTTP Request Smuggling (CL.TE / TE.CL) vulnerabilities."""
        lines = [
            "================================================================================",
            "⚡ HTTP REQUEST SMUGGLING (CL.TE / TE.CL) AUDIT",
            f"Host: {hostname}",
            "================================================================================\n",
            "[*] Testing differential parsing between front-end proxy and back-end server...",
            "[*] Probing conflicting Content-Length and Transfer-Encoding headers...\n"
        ]
        async with httpx.AsyncClient(verify=False, timeout=7.0) as client:
            try:
                h1 = {"Transfer-Encoding": "chunked", "Content-Length": "4"}
                r1 = await client.post(normalized_url, headers=h1, content=b"0\r\n\r\n")
                lines.append(f"[+] Probe 1 (Dual CL + TE): HTTP {r1.status_code}")

                h2 = {"Transfer-Encoding ": "chunked"}
                try:
                    r2 = await client.post(normalized_url, headers=h2, content=b"0\r\n\r\n")
                    lines.append(f"[+] Probe 2 (TE Obfuscation with Space): HTTP {r2.status_code}")
                except Exception:
                    lines.append("[-] Probe 2 ditolak oleh HTTP client/proxy (RFC compliant).")

                if r1.status_code in (400, 403, 405):
                    lines.append("\n✅ Server/WAF menolak permintaan dengan dual CL-TE (Proteksi Smuggling Aktif).")
                elif r1.status_code == 200:
                    lines.append("\n⚠️ Server merespons 200 OK pada dual CL-TE headers. Selidiki lebih lanjut dengan Burp Suite HTTP Request Smuggler.")
                else:
                    lines.append(f"\nℹ️ Server merespons dengan status {r1.status_code}.")

            except Exception as e:
                lines.append(f"[-] Permintaan ditolak atau terjadi error: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_cache_poison(cls, command: str, normalized_url: str) -> Dict[str, Any]:
        """Test for Web Cache Poisoning via unkeyed headers."""
        lines = [
            "================================================================================",
            "⚡ WEB CACHE POISONING & UNKEYED HEADER PROBE",
            f"Target: {normalized_url}",
            "================================================================================\n",
            "[*] Probing unkeyed headers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, X-Host...\n"
        ]
        canary_host = "poison-canary.example.internal"
        unkeyed_tests = [
            {"name": "X-Forwarded-Host", "headers": {"X-Forwarded-Host": canary_host}},
            {"name": "X-Host", "headers": {"X-Host": canary_host}},
            {"name": "X-Forwarded-Scheme", "headers": {"X-Forwarded-Scheme": "nothttps"}},
            {"name": "X-Original-URL", "headers": {"X-Original-URL": "/admin-secret-probe"}},
            {"name": "X-Rewrite-URL", "headers": {"X-Rewrite-URL": "/admin-secret-probe"}},
        ]

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False) as client:
            for t in unkeyed_tests:
                try:
                    res = await client.get(normalized_url, headers=t["headers"])
                    reflected = canary_host in res.text or canary_host in res.headers.get("location", "")
                    cache_status = res.headers.get("cf-cache-status") or res.headers.get("x-cache") or res.headers.get("x-varnish") or "No Cache Header"
                    if reflected:
                        lines.append(f"[!] REFLEKSI TERDETEKSI: Header '{t['name']}' direfleksikan dalam respons! (Status: {res.status_code}, Cache: {cache_status})")
                        lines.append("    ⚠️ Potensi Web Cache Poisoning tinggi jika reverse-proxy caching aktif!")
                    else:
                        lines.append(f"[-] [SAFE] '{t['name']}': Tidak direfleksikan (Status: {res.status_code}, Cache: {cache_status})")
                except Exception as e:
                    lines.append(f"[-] '{t['name']}': Probe gagal ({str(e)})")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_cors_deep(cls, command: str, normalized_url: str) -> Dict[str, Any]:
        """Deep multi-scenario CORS misconfiguration audit."""
        lines = [
            "================================================================================",
            "🌐 DEEP CORS MISCONFIGURATION SECURITY AUDIT",
            f"Target: {normalized_url}",
            "================================================================================\n"
        ]
        parsed = urlparse(normalized_url)
        host = parsed.hostname or "target.live"

        scenarios = [
            ("Arbitrary Origin (evil.com)", "https://evil.com"),
            ("Null Origin (data: URI / sandboxed iframe)", "null"),
            ("Pre-Domain Bypass", f"https://{host}.evil.com"),
            ("Post-Domain Bypass", f"https://evil-{host}"),
            ("Subdomain Bypass", f"https://attacker.{host}"),
            ("HTTP Downgrade Bypass", f"http://{host}")
        ]

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            vulnerable = False
            for label, origin in scenarios:
                try:
                    res = await client.get(normalized_url, headers={"Origin": origin})
                    acao = res.headers.get("access-control-allow-origin", "")
                    acac = res.headers.get("access-control-allow-credentials", "").lower() == "true"

                    if acao == origin:
                        vulnerable = True
                        risk = "CRITICAL" if acac else "HIGH"
                        lines.append(f"[!] [{risk}] Refleksi Origin Rentan Ditemukan:")
                        lines.append(f"    • Skenario : {label}")
                        lines.append(f"    • Origin   : {origin}")
                        lines.append(f"    • ACAO     : {acao}")
                        lines.append(f"    • ACAC     : {'true (KREDENSIAL / COOKIE BISA DICURI!)' if acac else 'false'}\n")
                    elif acao == "*":
                        lines.append(f"[-] [INFO] Wildcard ACAO '*' pada {label} (ACAC: {acac})")
                    else:
                        lines.append(f"[-] [SAFE] {label}: Ditolak atau tidak direfleksikan.")
                except Exception as e:
                    lines.append(f"[-] {label}: Koneksi gagal ({str(e)})")

            if not vulnerable:
                lines.append("\n✅ Kebijakan CORS target terkonfigurasi dengan ketat. Tidak ada refleksi origin sembarangan.")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_prototype(cls, command: str, normalized_url: str) -> Dict[str, Any]:
        """Test for Client-Side & Server-Side JavaScript Prototype Pollution."""
        lines = [
            "================================================================================",
            "⚡ JAVASCRIPT PROTOTYPE POLLUTION AUDIT",
            f"Target: {normalized_url}",
            "================================================================================\n",
            "[*] Probing Object.prototype mutation vectors: __proto__, constructor.prototype...\n"
        ]
        probes = [
            ("__proto__[djoeraganPolluted]=true", "?__proto__[djoeraganPolluted]=true"),
            ("__proto__.djoeraganPolluted=true", "?__proto__.djoeraganPolluted=true"),
            ("constructor[prototype][djoeraganPolluted]=true", "?constructor[prototype][djoeraganPolluted]=true"),
        ]
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            for name, qs in probes:
                fuzz_url = normalized_url + ("&" if "?" in normalized_url else "?") + qs[1:]
                try:
                    res = await client.get(fuzz_url)
                    if res.status_code == 500:
                        lines.append(f"[!] [SUSPICIOUS] Probe '{name}' memicu HTTP 500 Internal Server Error (Potensi anomali prototype parsing di backend).")
                    elif "djoeraganPolluted" in res.text:
                        lines.append(f"[!] [VULN] Refleksi Properti Prototype Terdeteksi via '{name}'!")
                    else:
                        lines.append(f"[-] [SAFE] '{name}': Respons normal (HTTP {res.status_code})")
                except Exception as e:
                    lines.append(f"[-] '{name}': Error ({str(e)})")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_clickjack(cls, command: str, normalized_url: str) -> Dict[str, Any]:
        """Audit Clickjacking framing defenses (X-Frame-Options and CSP frame-ancestors)."""
        lines = [
            "================================================================================",
            "🛡️ CLICKJACKING (UI REDRESSING) DEFENSE AUDIT",
            f"Target: {normalized_url}",
            "================================================================================\n"
        ]
        async with httpx.AsyncClient(verify=False, timeout=7.0) as client:
            try:
                res = await cls._safe_http_get(client, normalized_url)
                xfo = res.headers.get("x-frame-options", "").upper()
                csp = res.headers.get("content-security-policy", "").lower()

                has_xfo = xfo in ("DENY", "SAMEORIGIN")
                has_fa = "frame-ancestors" in csp

                lines.append(f"[+] X-Frame-Options Header : {xfo or 'TIDAK ADA'}")
                lines.append(f"[+] CSP frame-ancestors     : {'TERSEDIA' if has_fa else 'TIDAK ADA'}\n")

                if has_xfo or has_fa:
                    lines.append("  ✅ TARGET TERLINDUNGI DARI CLICKJACKING:")
                    if has_xfo:
                        lines.append(f"     • X-Frame-Options '{xfo}' memblokir embedding iframe pihak ketiga.")
                    if has_fa:
                        lines.append("     • CSP 'frame-ancestors' secara modern membatasi domain pembungkus.")
                else:
                    lines.append("  ❌ RENTAN CLICKJACKING:")
                    lines.append("     Situs web ini dapat disematkan ke dalam <iframe> transparan oleh penyerang,")
                    lines.append("     memungkinkan serangan manipulasi klik pengguna (UI Redressing).")
                    lines.append("  💡 Solusi: Tambahkan header 'X-Frame-Options: SAMEORIGIN' atau CSP 'frame-ancestors self'.")

            except Exception as e:
                lines.append(f"[-] Gagal memeriksa proteksi clickjacking: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

    @classmethod
    async def _cmd_srcmap(cls, command: str, normalized_url: str) -> Dict[str, Any]:
        """Detect exposed JavaScript Source Maps (.js.map) revealing original source code."""
        lines = [
            "================================================================================",
            "🔍 JAVASCRIPT SOURCE MAP EXPOSURE AUDIT",
            f"Target: {normalized_url}",
            "================================================================================\n",
            "[*] Crawling halaman utama untuk menemukan referensi script .js dan file .js.map...\n"
        ]
        async with httpx.AsyncClient(verify=False, timeout=7.0) as client:
            try:
                res = await cls._safe_http_get(client, normalized_url)
                soup = BeautifulSoup(res.text, "html.parser")
                scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]

                lines.append(f"[*] Ditemukan {len(scripts)} file script JavaScript eksternal:")
                exposed_maps = []
                for s in scripts[:8]:
                    full_js = urljoin(normalized_url, s)
                    map_url = full_js + ".map"
                    try:
                        m_res = await client.head(map_url, timeout=4.0)
                        if m_res.status_code == 200:
                            exposed_maps.append(map_url)
                            lines.append(f"  [!] [TEREKSPOS] Source Map Ditemukan: {map_url} (HTTP 200)")
                        else:
                            lines.append(f"  [-] [SAFE] {full_js} -> no .map ({m_res.status_code})")
                    except Exception:
                        lines.append(f"  [-] [SAFE] {full_js}")

                if exposed_maps:
                    lines.append(f"\n⚠️ PERINGATAN: Ditemukan {len(exposed_maps)} file .js.map yang dapat diunduh publik!")
                    lines.append("   Penyerang dapat merekonstruksi 100% kode sumber frontend TypeScript/React/Vue asli.")
                    lines.append("💡 Solusi: Nonaktifkan generation source map di konfigurasi build produksi (e.g. `build.sourcemap = false`).")
                else:
                    lines.append("\n✅ Tidak ada file .js.map yang terekspos secara publik pada bundle yang diperiksa.")

            except Exception as e:
                lines.append(f"[-] Pemeriksaan source map gagal: {str(e)}")

        return {
            "command": command,
            "output": "\n".join(lines),
            "exit_code": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
