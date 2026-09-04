import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.scan import Scan, Vulnerability
from app.core.ssrf_guard import validate_and_sanitize_target
from app.engine.passive.header_analyzer import SecurityHeaderAnalyzer
from app.engine.passive.ssl_tls_checker import SSLTLSChecker
from app.engine.passive.cookie_auditor import CookieSecurityAuditor
from app.engine.passive.tech_detector import TechnologyDetector
from app.engine.passive.domain_relations import DomainRelationsAnalyzer
from app.engine.passive.subdomain_enum import SubdomainEnumerator
from app.engine.passive.cve_fingerprint import CVEFingerprintEngine
from app.engine.passive.email_finder import TargetEmailDetector
from app.engine.active.cors_analyzer import CORSAnalyzer
from app.engine.active.csp_analyzer import CSPAnalyzer
from app.engine.active.crawler import WebCrawler
from app.engine.active.dir_fuzzer import SensitiveFileAuditor
from app.engine.active.xss_analyzer import XSSAnalyzer
from app.engine.active.sqli_detector import SQLiDetector
from app.engine.active.ssti_detector import SSTIDetector
from app.engine.active.open_redirect_detector import OpenRedirectDetector
from app.engine.active.lfi_detector import LFIDetector
from app.engine.active.jwt_analyzer import JWTAnalyzer
from app.engine.active.input_validator import InputResilienceValidator
from app.engine.active.db_integrity_checker import DatabaseIntegrityAuditor
from app.engine.scoring.cvss_v3 import CVSSv31Calculator
from app.engine.live.live_engine import LiveAuditEngine
from app.api.v1.ws import broadcast_scan_event

async def run_scan_pipeline(scan_id: int, target_url: str, profile: str = "passive"):
    """
    Pipeline eksekusi pemindaian kerentanan web end-to-end (2026 Enterprise Edition).
    Mendukung Passive Intelligence, Subdomain Enum, CVE Fingerprinting,
    serta Active Fuzzing (XSS, SQLi, SSTI, Open Redirect, LFI, JWT, Dir Fuzzing).
    """
    try:
        from app.core.database import init_db
        await init_db()
    except Exception as e:
        print(f"[TASK INIT DB WARNING] {e}")

    async with AsyncSessionLocal() as session:
        # Load Scan Record
        res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if not scan:
            return

        async def emit_log(msg: str):
            await broadcast_scan_event(scan_id, {"type": "log", "message": msg})

        try:
            # Stage 1: Validation & SSRF Guard
            scan.status = "INITIALIZING"
            scan.progress = 5
            await session.commit()
            await emit_log(f"[INIT] Validating target URL '{target_url}' against SSRF & Blacklists...")

            is_valid, normalized_url, err_msg = validate_and_sanitize_target(target_url)
            if not is_valid:
                scan.status = "FAILED"
                await session.commit()
                await emit_log(f"[ERROR] Target validation failed: {err_msg}")
                await broadcast_scan_event(scan_id, {"type": "done", "status": "FAILED", "error": err_msg})
                return

            findings: List[Dict[str, Any]] = []

            # Stage 2: Passive Security Analysis
            scan.status = "ANALYZING_PASSIVE"
            scan.progress = 15
            await session.commit()
            await emit_log("[PASSIVE] Running HTTP Security Headers analysis...")

            header_analyzer = SecurityHeaderAnalyzer()
            header_findings = await header_analyzer.analyze(normalized_url)
            findings.extend(header_findings)

            await emit_log("[PASSIVE] Checking SSL/TLS protocol, cipher grading (A+ to F), and certificate validity...")
            ssl_checker = SSLTLSChecker()
            ssl_findings = await ssl_checker.analyze(normalized_url)
            findings.extend(ssl_findings)

            await emit_log("[PASSIVE] Auditing cookie security attributes (HttpOnly, Secure, SameSite)...")
            cookie_auditor = CookieSecurityAuditor()
            cookie_findings = await cookie_auditor.analyze(normalized_url)
            findings.extend(cookie_findings)

            await emit_log("[PASSIVE] Detecting technology stack & banner disclosures...")
            tech_detector = TechnologyDetector()
            tech_findings = await tech_detector.analyze(normalized_url)
            findings.extend(tech_findings)

            await emit_log("[PASSIVE] Auditing Cross-Origin Resource Sharing (CORS) security policies...")
            cors_analyzer = CORSAnalyzer()
            cors_findings = await cors_analyzer.analyze(normalized_url)
            findings.extend(cors_findings)

            await emit_log("[PASSIVE] Performing deep Content Security Policy (CSP) directive analysis...")
            csp_analyzer = CSPAnalyzer()
            csp_findings = await csp_analyzer.analyze(normalized_url)
            findings.extend(csp_findings)

            # Stage 2.5: Domain & SSL Cross-Website Relations & History Intelligence
            scan.progress = 25
            await session.commit()
            await emit_log("[PASSIVE] Analyzing SSL Subject Alternative Names (SANs) & Certificate Transparency History...")
            domain_analyzer = DomainRelationsAnalyzer()
            domain_intel = await domain_analyzer.analyze(normalized_url, emit_log=emit_log)
            
            if domain_intel.get("findings"):
                findings.extend(domain_intel["findings"])

            # Stage 2.6: Live WAF & Open Web Ports Probing
            scan.progress = 28
            await session.commit()
            await emit_log("[PASSIVE] Fingerprinting WAF / CDN edge security & probing standard ports...")
            try:
                waf_res = await LiveAuditEngine.execute_live_command("waf", normalized_url)
                ports_res = await LiveAuditEngine.execute_live_command("ports", normalized_url)
                domain_intel["waf_summary"] = waf_res.get("output", "")
                domain_intel["ports_summary"] = ports_res.get("output", "")
            except Exception:
                pass

            # Stage 2.7: Target Website Email, Contact & Security.txt Reconnaissance
            scan.progress = 30
            await session.commit()
            await emit_log("[PASSIVE] Detecting website official contact emails, RFC 9116 security.txt, and Gmail / Google Workspace MX...")
            try:
                email_recon = await TargetEmailDetector.detect(normalized_url)
                domain_intel["email_recon"] = email_recon
                if email_recon.get("primary_email"):
                    await emit_log(f"[INTEL] Target contact email identified: {email_recon['primary_email']} ({email_recon.get('source_label')})")
            except Exception:
                domain_intel["email_recon"] = None

            # Stage 2.8: Subdomain Enumeration (crt.sh CT + DNS Brute-Force)
            scan.progress = 34
            await session.commit()
            await emit_log("[PASSIVE] Enumerating subdomains via Certificate Transparency (crt.sh) and DNS brute-force...")
            try:
                subdomain_enumerator = SubdomainEnumerator()
                sub_res = await subdomain_enumerator.enumerate(normalized_url, emit_log=emit_log)
                domain_intel["subdomains"] = sub_res.get("subdomains_found", [])
                domain_intel["all_subdomains"] = sub_res.get("all_discovered", [])
                
                # Check for dangling subdomains / takeover vulnerability
                for dangling in sub_res.get("subdomains_dangling", []):
                    findings.append({
                        "title": f"Subdomain Takeover Potential: {dangling['subdomain']}",
                        "severity": "High",
                        "cwe": "CWE-284",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "description": (
                            f"Subdomain {dangling['subdomain']} mengarah ke layanan pihak ketiga ({dangling.get('provider')}) "
                            "yang belum diklaim atau sudah tidak aktif (dangling DNS record). Penyerang dapat mengambil alih subdomain ini."
                        ),
                        "remediation": f"Hapus CNAME DNS record untuk {dangling['subdomain']} atau klaim kembali layanannya.",
                        "evidence": f"Unclaimed service detected on provider: {dangling.get('provider')}",
                        "target_url": f"https://{dangling['subdomain']}"
                    })
            except Exception as e:
                domain_intel["subdomains"] = []

            # Stage 2.9: CVE Fingerprint Engine (Banner to CVE)
            scan.progress = 38
            await session.commit()
            await emit_log("[PASSIVE] Matching technology stack banners against CVE Vulnerability Database...")
            try:
                cve_engine = CVEFingerprintEngine()
                cve_findings = await cve_engine.scan(normalized_url, emit_log=emit_log)
                findings.extend(cve_findings)
            except Exception as e:
                pass

            # Store domain intelligence in scan record
            scan.domain_intel = json.dumps(domain_intel)
            await session.commit()

            # Broadcast domain intelligence event to frontend
            await broadcast_scan_event(scan_id, {
                "type": "domain_intel",
                "data": domain_intel
            })

            # Stage 3: Active Crawling & Fuzzing (If Active Profile Selected)
            discovered_urls = [normalized_url]
            discovered_forms = []
            if profile.lower() == "active":
                scan.status = "CRAWLING"
                scan.progress = 42
                await session.commit()
                await emit_log("[ACTIVE] Starting modern asynchronous web spider with SPA & JS API endpoint mining...")

                crawler = WebCrawler(max_pages=25, max_depth=3)
                crawl_res = await crawler.crawl(normalized_url, emit_log=emit_log)
                discovered_urls = crawl_res["urls"]
                discovered_forms = crawl_res.get("forms", [])

                domain_intel["discovered_urls"] = discovered_urls
                domain_intel["discovered_forms"] = discovered_forms
                domain_intel["api_endpoints"] = crawl_res.get("api_endpoints", [])
                domain_intel["websocket_endpoints"] = crawl_res.get("websocket_endpoints", [])
                scan.domain_intel = json.dumps(domain_intel)
                await session.commit()

                # Stage 3.1: Sensitive File & Backup Directory Fuzzing
                scan.status = "FUZZING"
                scan.progress = 52
                await session.commit()
                await emit_log(f"[ACTIVE] Discovered {len(discovered_urls)} endpoints. Fuzzing 250+ sensitive paths (SecLists, backups, cloud metadata)...")

                dir_fuzzer = SensitiveFileAuditor()
                dir_findings = await dir_fuzzer.scan(normalized_url, emit_log=emit_log)
                findings.extend(dir_findings)

                # Stage 3.2: Reflected XSS & DOM Sink Fuzzing
                scan.progress = 62
                await session.commit()
                await emit_log("[ACTIVE] Fuzzing query parameters and forms for Reflected XSS, DOM sinks, and polyglots...")
                xss_fuzzer = XSSAnalyzer()
                xss_findings = await xss_fuzzer.scan_urls(discovered_urls, forms=discovered_forms, emit_log=emit_log)
                findings.extend(xss_findings)

                # Stage 3.3: SQL & NoSQL Injection Fuzzing
                scan.progress = 72
                await session.commit()
                await emit_log("[ACTIVE] Testing endpoints for SQL Injection (Error, Boolean, Time) & NoSQL Injection...")
                sqli_fuzzer = SQLiDetector()
                sqli_findings = await sqli_fuzzer.scan_urls(discovered_urls, forms=discovered_forms, emit_log=emit_log)
                findings.extend(sqli_findings)

                # Stage 3.4: Input & Search Resilience Validation
                scan.progress = 78
                await session.commit()
                await emit_log("[ACTIVE] Running Input & Search Resilience validation on forms and query parameters...")
                input_validator = InputResilienceValidator()
                input_findings = await input_validator.scan_candidate_inputs(discovered_urls, discovered_forms, emit_log=emit_log)
                findings.extend(input_findings)

                # Stage 3.5: Database Privilege & Boundary Audit
                scan.progress = 82
                await session.commit()
                await emit_log("[ACTIVE] Running Database Privilege & Least Privilege Boundary Audit...")
                db_integrity = DatabaseIntegrityAuditor()
                db_findings = await db_integrity.scan_boundary_resilience(discovered_urls, emit_log=emit_log)
                findings.extend(db_findings)

                # Stage 3.6: Server-Side Template Injection (SSTI)
                scan.progress = 86
                await session.commit()
                await emit_log("[ACTIVE] Fuzzing parameters for Server-Side Template Injection (Jinja2, Twig, Freemarker, Pebble)...")
                try:
                    ssti_fuzzer = SSTIDetector()
                    ssti_findings = await ssti_fuzzer.scan_urls(discovered_urls, forms=discovered_forms, emit_log=emit_log)
                    findings.extend(ssti_findings)
                except Exception as e:
                    pass

                # Stage 3.7: Open Redirect Parameter Fuzzing
                scan.progress = 89
                await session.commit()
                await emit_log("[ACTIVE] Testing query parameters for Open Redirect with 35+ protocol & encoding bypass payloads...")
                try:
                    redirect_fuzzer = OpenRedirectDetector()
                    redirect_findings = await redirect_fuzzer.scan_urls(discovered_urls, forms=discovered_forms, emit_log=emit_log)
                    findings.extend(redirect_findings)
                except Exception as e:
                    pass

                # Stage 3.8: Local File Inclusion & Path Traversal
                scan.progress = 92
                await session.commit()
                await emit_log("[ACTIVE] Testing parameters for Local File Inclusion (LFI) & Directory Path Traversal...")
                try:
                    lfi_fuzzer = LFIDetector()
                    lfi_findings = await lfi_fuzzer.scan_urls(discovered_urls, forms=discovered_forms, emit_log=emit_log)
                    findings.extend(lfi_findings)
                except Exception as e:
                    pass

                # Stage 3.9: JWT Token Security Analysis
                scan.progress = 95
                await session.commit()
                await emit_log("[ACTIVE] Analyzing responses & endpoints for exposed JSON Web Tokens (alg:none, weak secret, claims)...")
                try:
                    jwt_analyzer = JWTAnalyzer()
                    jwt_findings = await jwt_analyzer.scan_urls(discovered_urls, forms=discovered_forms, emit_log=emit_log)
                    findings.extend(jwt_findings)
                except Exception as e:
                    pass

            # Stage 4: Scoring, Aggregation & Database Storage
            scan.status = "REPORTING"
            scan.progress = 97
            await session.commit()
            await emit_log(f"[SCORING] Processing {len(findings)} findings through CVSS v3.1 calculation engine...")

            crit_count = high_count = med_count = low_count = info_count = 0

            for f in findings:
                vector = f.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
                calc_result = CVSSv31Calculator.calculate(vector)
                
                score = calc_result["score"]
                sev = f.get("severity") or calc_result["severity"]

                vuln_record = Vulnerability(
                    scan_id=scan.id,
                    title=f.get("title", "Unknown Vulnerability"),
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_category=f.get("owasp_category", "A05:2021-Security Misconfiguration"),
                    cwe=f.get("cwe", "CWE-200"),
                    description=f.get("description", ""),
                    remediation=f.get("remediation", ""),
                    evidence=f.get("evidence", ""),
                    target_url=f.get("target_url", normalized_url),
                )
                session.add(vuln_record)

                if sev == "Critical":
                    crit_count += 1
                elif sev == "High":
                    high_count += 1
                elif sev == "Medium":
                    med_count += 1
                elif sev == "Low":
                    low_count += 1
                else:
                    info_count += 1

                # Broadcast live finding to UI
                await broadcast_scan_event(scan_id, {
                    "type": "finding",
                    "finding": {
                        "title": f.get("title"),
                        "severity": sev,
                        "cvss_score": score,
                        "owasp_category": f.get("owasp_category"),
                        "cwe": f.get("cwe"),
                        "remediation": f.get("remediation"),
                        "target_url": f.get("target_url")
                    }
                })

            scan.total_findings = len(findings)
            scan.critical_count = crit_count
            scan.high_count = high_count
            scan.medium_count = med_count
            scan.low_count = low_count
            scan.info_count = info_count
            scan.status = "COMPLETED"
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            await session.commit()

            await emit_log(f"[COMPLETED] Scan finished successfully with {len(findings)} findings (Critical: {crit_count}, High: {high_count}, Medium: {med_count}, Low: {low_count}, Info: {info_count}).")
            await broadcast_scan_event(scan_id, {"type": "done", "status": "COMPLETED"})

        except Exception as e:
            scan.status = "FAILED"
            await session.commit()
            await emit_log(f"[FATAL] Scan pipeline crashed: {str(e)}")
            await broadcast_scan_event(scan_id, {"type": "done", "status": "FAILED", "error": str(e)})
