import ssl
import socket
import httpx
import asyncio
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Tuple

def extract_root_domain(hostname: str) -> str:
    """
    Ekstraksi root domain dasar (mendukung format umum seperti .co.id, .com, .org, dll).
    """
    if not hostname:
        return ""
    parts = hostname.lower().strip().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    
    # Deteksi two-level TLDs umum (e.g. .co.id, .ac.id, .go.id, .or.id, .net.id, .web.id, .co.uk, .org.uk, .com.au, .com.br, .co.jp)
    two_level_tlds = {"co.id", "ac.id", "go.id", "or.id", "net.id", "web.id", "co.uk", "org.uk", "com.au", "com.br", "co.jp"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_level_tlds:
        return ".".join(parts[-3:])
    
    return ".".join(parts[-2:])

class DomainRelationsAnalyzer:
    """
    Menganalisis keterhubungan domain/SSL dengan website lain dan histori Certificate Transparency (CT Logs).
    """

    async def analyze(self, target_url: str, emit_log=None) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return {}

        root_domain = extract_root_domain(hostname)

        results: Dict[str, Any] = {
            "target_domain": hostname,
            "root_domain": root_domain,
            "current_ssl": {
                "issuer": None,
                "common_name": None,
                "not_before": None,
                "not_after": None,
                "serial_number": None,
            },
            "san_domains": [],               # Seluruh SAN pada sertifikat aktif
            "same_domain_subdomains": [],    # Subdomain dari root domain yang sama
            "cross_website_domains": [],     # Domain website lain yang berbagi sertifikat SSL sama
            "is_shared_ssl": False,
            "ip_addresses": [],
            "reverse_ptr_hosts": [],         # Reverse DNS PTR hosts
            "historical_certificates": [],   # Histori sertifikat dari Certificate Transparency (CT Logs)
            "historical_subdomains": [],     # Subdomain masa lalu dari CT Logs
            "historical_cross_domains": [],  # Domain lain yang pernah tercatat di histori sertifikat
            "findings": [],                  # Temuan kerentanan pasif terkait relasi domain/SSL
            "relationship_summary": "",
            "risk_level": "Low"
        }

        # 1. Ekstraksi Sertifikat SSL Aktif & Subject Alternative Names (SANs)
        try:
            if emit_log:
                await emit_log(f"[INTEL] Inspecting active SSL Certificate & Subject Alternative Names (SANs) for {hostname}...")

            context = ssl.create_default_context()
            port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 443)

            # Non-blocking socket connect & SSL handshake
            loop = asyncio.get_event_loop()
            
            def get_ssl_cert_sync():
                with socket.create_connection((hostname, port), timeout=6.0) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        return ssock.getpeercert()

            cert = await loop.run_in_executor(None, get_ssl_cert_sync)

            if cert:
                # Ambil Issuer & Common Name
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                
                results["current_ssl"]["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"
                results["current_ssl"]["common_name"] = subject_dict.get("commonName")
                results["current_ssl"]["not_before"] = cert.get("notBefore")
                results["current_ssl"]["not_after"] = cert.get("notAfter")
                results["current_ssl"]["serial_number"] = cert.get("serialNumber")

                sans = []
                for item in cert.get("subjectAltName", ()):
                    if item[0] == "DNS":
                        sans.append(item[1].lower())

                sans = sorted(list(set(sans)))
                results["san_domains"] = sans

                same_subs = []
                cross_domains = []

                for d in sans:
                    d_clean = d.replace("*.", "")
                    d_root = extract_root_domain(d_clean)
                    if d_root == root_domain:
                        same_subs.append(d)
                    else:
                        cross_domains.append(d)

                results["same_domain_subdomains"] = same_subs
                results["cross_website_domains"] = cross_domains

                if len(cross_domains) > 0:
                    results["is_shared_ssl"] = True
                    results["risk_level"] = "Medium"
                    
                    if emit_log:
                        await emit_log(f"[INTEL-WARN] Target shares active SSL certificate with {len(cross_domains)} external website(s): {', '.join(cross_domains[:3])}...")

                    # Buat temuan keamanan untuk Multi-Domain Shared SSL
                    results["findings"].append({
                        "title": f"Multi-Tenant / Shared SSL Certificate with External Domains ({len(cross_domains)} other domains)",
                        "severity": "Low",
                        "cwe": "CWE-668",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", # 5.3 Medium/Low
                        "description": (
                            f"Domain '{hostname}' berbagi sertifikat SSL (SAN) dengan domain website lain di luar root domain '{root_domain}': "
                            f"{', '.join(cross_domains[:5])}{'...' if len(cross_domains) > 5 else ''}. "
                            f"Kondisi ini umum pada shared CDN/hosting multi-tenant, namun mengindikasikan infrastruktur terminasi TLS dibagi dengan entitas luar."
                        ),
                        "remediation": "Pertimbangkan untuk menggunakan Dedicated SSL Certificate (SNI) tersendiri guna mengisolasi domain dari asosiasi sertifikat domain pihak ketiga.",
                        "evidence": f"Cross-Domain SANs: {', '.join(cross_domains[:10])}",
                        "target_url": target_url
                    })

        except Exception as e:
            if emit_log:
                await emit_log(f"[INTEL] Active SSL cert inspection note: {str(e)}")

        # 2. IP Resolution & Reverse DNS (PTR) Lookup
        try:
            if emit_log:
                await emit_log(f"[INTEL] Resolving IP addresses and Reverse DNS (PTR) for {hostname}...")

            loop = asyncio.get_event_loop()

            def resolve_dns_sync():
                ip_set = set()
                ptr_set = set()
                try:
                    addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
                    for item in addr_info:
                        ip_str = item[4][0]
                        ip_set.add(ip_str)
                        try:
                            host, _, _ = socket.gethostbyaddr(ip_str)
                            if host and host.lower() != hostname.lower():
                                ptr_set.add(host.lower())
                        except Exception:
                            pass
                except Exception:
                    pass
                return list(ip_set), list(ptr_set)

            ip_list, ptr_list = await loop.run_in_executor(None, resolve_dns_sync)
            results["ip_addresses"] = ip_list
            results["reverse_ptr_hosts"] = ptr_list

            if ptr_list and emit_log:
                await emit_log(f"[INTEL] Resolved {len(ip_list)} IP(s) and {len(ptr_list)} PTR hostname(s): {', '.join(ptr_list[:3])}")

        except Exception as e:
            if emit_log:
                await emit_log(f"[INTEL] DNS lookup note: {str(e)}")

        # 3. Histori Certificate Transparency (CT Logs) via crt.sh
        try:
            if emit_log:
                await emit_log(f"[INTEL] Querying Certificate Transparency (CT Logs) history for historical certificate associations...")

            ct_url = f"https://crt.sh/?q=%.{root_domain}&output=json"
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                resp = await client.get(ct_url, headers={"User-Agent": "VulnHunter-ThreatIntel/1.0"})
                if resp.status_code == 200:
                    ct_data = resp.json()
                    subdomains_found: Set[str] = set()
                    historical_cross: Set[str] = set()
                    cert_history: List[Dict[str, Any]] = []
                    seen_serials: Set[str] = set()

                    for entry in ct_data:
                        serial = str(entry.get("serial_number") or entry.get("id") or "")
                        if serial and serial in seen_serials:
                            continue
                        if serial:
                            seen_serials.add(serial)

                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if not name:
                                continue
                            
                            n_clean = name.replace("*.", "")
                            n_root = extract_root_domain(n_clean)
                            if n_root == root_domain:
                                subdomains_found.add(name)
                            else:
                                historical_cross.add(name)

                        if len(cert_history) < 15:
                            issuer_raw = entry.get("issuer_name", "")
                            issuer_cleaned = "Unknown Issuer"
                            for part in issuer_raw.split(","):
                                if "O=" in part or "CN=" in part:
                                    issuer_cleaned = part.replace("O=", "").replace("CN=", "").strip()
                                    break

                            cert_history.append({
                                "id": entry.get("id"),
                                "issuer": issuer_cleaned,
                                "logged_at": entry.get("entry_timestamp", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                                "common_name": entry.get("common_name", ""),
                                "name_value": name_value[:150]
                            })

                    results["historical_subdomains"] = sorted(list(subdomains_found))[:50]
                    results["historical_cross_domains"] = sorted(list(historical_cross))[:30]
                    results["historical_certificates"] = cert_history

                    if emit_log:
                        await emit_log(f"[INTEL] Discovered {len(results['historical_subdomains'])} historical subdomains and {len(cert_history)} CT certificates.")
        except Exception as e:
            # Fallback jika service crt.sh offline atau timeout
            if emit_log:
                await emit_log(f"[INTEL] CT Logs lookup skipped or timed out ({str(e)}). Proceeding...")

        # 4. Ringkasan Keterhubungan (Relationship Intelligence Summary)
        san_total = len(results["san_domains"])
        cross_count = len(results["cross_website_domains"])
        hist_sub_count = len(results["historical_subdomains"])
        hist_cross_count = len(results["historical_cross_domains"])
        ptr_count = len(results["reverse_ptr_hosts"])

        summary_parts = []
        if san_total > 0:
            summary_parts.append(f"Sertifikat SSL aktif mencakup {san_total} domain/subdomain.")
        if cross_count > 0:
            summary_parts.append(f"⚠️ Terdeteksi Multi-Domain Shared SSL bersama {cross_count} domain luar ({', '.join(results['cross_website_domains'][:2])}).")
        if hist_sub_count > 0:
            summary_parts.append(f"Ditemukan {hist_sub_count} riwayat subdomain pada Certificate Transparency logs.")
        if hist_cross_count > 0:
            summary_parts.append(f"Arsip riwayat mencakup {hist_cross_count} domain eksternal terdahulu.")
        if ptr_count > 0:
            summary_parts.append(f"Reverse DNS PTR meresolusi ke {', '.join(results['reverse_ptr_hosts'][:2])}.")

        results["relationship_summary"] = " ".join(summary_parts) if summary_parts else "Tidak ditemukan relasi domain atau sertifikat eksternal."

        return results
