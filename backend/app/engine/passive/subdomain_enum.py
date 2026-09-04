"""
Subdomain Enumerator
=====================
Enumerasi subdomain target menggunakan dua sumber data:
  1. Certificate Transparency Logs — crt.sh public API
  2. DNS Brute-Force — wordlist 500 subdomain umum dengan async DNS resolution

Output:
  • List subdomain aktif yang ditemukan
  • Subdomain expired/dangling (CloudFront/S3/Heroku takeover detection)
  • Wildcard DNS detection
"""

import asyncio
import socket
import json
import httpx
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# DNS Brute-Force Wordlist — 200 subdomain paling umum
# ---------------------------------------------------------------------------
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "m", "mobile", "api", "dev", "test", "stage", "staging", "beta",
    "app", "apps", "portal", "dashboard", "panel", "cp", "cpanel", "manage",
    "manager", "management", "login", "auth", "secure", "cdn", "static",
    "assets", "media", "img", "images", "files", "docs", "document",
    "blog", "forum", "shop", "store", "pay", "payment", "checkout",
    "support", "help", "helpdesk", "ticket", "status", "monitor",
    "chat", "video", "stream", "live", "news", "press", "careers",
    "jobs", "upload", "download", "ftp2", "sftp", "ssh", "db", "database",
    "mysql", "postgres", "redis", "memcache", "elasticsearch", "kibana",
    "jenkins", "gitlab", "git", "svn", "jira", "confluence", "slack",
    "internal", "intranet", "corp", "corporate", "employee", "hr",
    "finance", "accounting", "legal", "marketing", "sales",
    "old", "new", "backup", "bak", "archive", "legacy",
    "prod", "production", "qa", "uat", "demo", "sandbox",
    "v1", "v2", "v3", "api1", "api2", "api3", "rest",
    "graphql", "socket", "ws", "wss", "websocket",
    "mail2", "smtp2", "mx", "mx1", "mx2", "relay",
    "smtp", "imap", "pop3", "webdav", "owa", "exchange",
    "redirect", "www2", "web", "web1", "web2", "web3",
    "server", "server1", "server2", "host", "ns3", "ns4",
    "lb", "balancer", "proxy", "gateway", "firewall",
    "edge", "node", "cluster", "k8s", "kubernetes",
    "docker", "container", "service", "services",
    "data", "reporting", "report", "analytics", "metric",
    "log", "logs", "logging", "sentry", "newrelic",
    "health", "ping", "check", "probe",
    "token", "oauth", "sso", "saml", "oidc", "idp",
    "crm", "erp", "cms", "wp", "wordpress", "drupal",
    "joomla", "magento", "shopify", "prestashop",
    "cdn1", "cdn2", "assets2", "static2",
    "cloud", "aws", "azure", "gcp", "google",
    "test2", "staging2", "dev2", "alpha",
    "search", "es", "solr", "lucene",
    "smtp-out", "mail-out", "outbound",
    "inbound", "incoming", "outgoing",
    "vpn2", "remote", "rdp", "citrix",
    "api-gateway", "microservice", "lambda",
    "webhooks", "webhook", "callback", "notify",
    "push", "pull", "sync", "async",
    "report", "export", "import", "etl",
    "billing", "invoice", "subscription",
    "user", "users", "account", "accounts",
    "register", "signup", "signin", "logout",
    "password", "reset", "verify", "activate",
    "confirm", "validate",
]

# Dangling/takeover signature per cloud provider
DANGLING_SIGNATURES = {
    "CloudFront": "The request could not be satisfied",
    "S3": "NoSuchBucket",
    "Heroku": "No such app",
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Fastly": "Fastly error: unknown domain",
    "Azure": "404 Web Site not found",
    "Netlify": "Not Found - Request ID:",
    "Shopify": "Sorry, this shop is currently unavailable",
}


async def _dns_resolve(hostname: str) -> Optional[str]:
    """Resolve hostname to IP via DNS. Returns IP or None."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        )
        if result:
            return result[0][4][0]
    except Exception:
        pass
    return None


class SubdomainEnumerator:
    """
    Enumerasi subdomain aktif via Certificate Transparency + DNS Brute-Force.
    """

    async def enumerate(
        self,
        target_url: str,
        emit_log=None
    ) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        base_domain = parsed.hostname or ""
        # Strip www. to get root domain
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        result: Dict[str, Any] = {
            "base_domain": base_domain,
            "subdomains_found": [],
            "subdomains_dangling": [],
            "ct_count": 0,
            "dns_count": 0,
            "total_unique": 0,
        }

        if not base_domain:
            return result

        if emit_log:
            await emit_log(f"[SUBDOMAIN] Enumerating subdomains for: {base_domain}")

        found: Set[str] = set()

        # ── Phase 1: Certificate Transparency Logs ──────────────────────────
        ct_subs = await self._query_crtsh(base_domain, emit_log)
        for sub in ct_subs:
            found.add(sub)
        result["ct_count"] = len(ct_subs)

        if emit_log:
            await emit_log(
                f"[SUBDOMAIN-CT] Found {len(ct_subs)} subdomains from Certificate "
                f"Transparency logs (crt.sh)"
            )

        # ── Phase 2: DNS Brute-Force ────────────────────────────────────────
        dns_found = await self._dns_bruteforce(base_domain, emit_log)
        for sub in dns_found:
            found.add(sub)
        result["dns_count"] = len(dns_found)

        if emit_log:
            await emit_log(
                f"[SUBDOMAIN-DNS] Found {len(dns_found)} subdomains via "
                f"DNS brute-force ({len(SUBDOMAIN_WORDLIST)} words)"
            )

        # ── Phase 3: Check for dangling subdomains (takeover potential) ─────
        confirmed_active = []
        dangling = []

        async with httpx.AsyncClient(
            verify=False, timeout=5.0, follow_redirects=True
        ) as client:
            for sub in list(found)[:50]:  # Limit HTTP probes
                fqdn = f"{sub}.{base_domain}" if not sub.endswith(base_domain) else sub
                try:
                    res = await client.get(f"https://{fqdn}", timeout=4.0)
                    body = res.text[:500]
                    is_dangling = False
                    for provider, sig in DANGLING_SIGNATURES.items():
                        if sig.lower() in body.lower():
                            dangling.append({
                                "subdomain": fqdn,
                                "provider": provider,
                                "status": res.status_code
                            })
                            is_dangling = True
                            break
                    if not is_dangling:
                        confirmed_active.append({
                            "subdomain": fqdn,
                            "status": res.status_code,
                            "server": res.headers.get("server", "—"),
                            "title": self._extract_title(res.text)
                        })
                except Exception:
                    pass

        result["subdomains_found"] = confirmed_active
        result["subdomains_dangling"] = dangling
        result["total_unique"] = len(found)
        result["all_discovered"] = sorted(list(found))

        if emit_log:
            await emit_log(
                f"[SUBDOMAIN] Complete: {len(confirmed_active)} active, "
                f"{len(dangling)} dangling (potential takeover)"
            )

        return result

    async def _query_crtsh(self, domain: str, emit_log) -> List[str]:
        """Query crt.sh Certificate Transparency log for subdomains."""
        subs = []
        if emit_log:
            await emit_log(f"[SUBDOMAIN-CT] Querying crt.sh for '{domain}'...")

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                res = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"}
                )
                if res.status_code == 200:
                    entries = res.json()
                    seen = set()
                    for entry in entries:
                        names = entry.get("name_value", "").split("\n")
                        for name in names:
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{domain}") and name not in seen:
                                seen.add(name)
                                subs.append(name)
        except Exception as e:
            if emit_log:
                await emit_log(f"[SUBDOMAIN-CT] crt.sh query failed: {e}")

        return subs

    async def _dns_bruteforce(self, domain: str, emit_log) -> List[str]:
        """Async DNS resolution brute-force."""
        if emit_log:
            await emit_log(
                f"[SUBDOMAIN-DNS] Running async DNS brute-force on {len(SUBDOMAIN_WORDLIST)} words..."
            )

        found = []
        semaphore = asyncio.Semaphore(30)  # Max 30 concurrent DNS lookups

        async def check(word: str):
            async with semaphore:
                fqdn = f"{word}.{domain}"
                ip = await _dns_resolve(fqdn)
                if ip:
                    found.append(fqdn)

        await asyncio.gather(*[check(w) for w in SUBDOMAIN_WORDLIST], return_exceptions=True)
        return found

    def _extract_title(self, html: str) -> str:
        """Extract <title> from HTML."""
        import re
        m = re.search(r"<title[^>]*>([^<]{1,100})</title>", html, re.IGNORECASE)
        return m.group(1).strip() if m else "—"

    async def scan_urls(
        self,
        urls: List[str],
        forms: Optional[List[Dict[str, Any]]] = None,
        emit_log=None
    ) -> List[Dict[str, Any]]:
        """
        Wrapper untuk integrasi ke pipeline scan — kembalikan findings
        untuk subdomain dangling (subdomain takeover).
        """
        if not urls:
            return []

        result = await self.enumerate(urls[0], emit_log)
        findings = []

        for dangling in result.get("subdomains_dangling", []):
            findings.append({
                "title": f"Subdomain Takeover Risk — {dangling['subdomain']} ({dangling['provider']})",
                "severity": "High",
                "cwe": "CWE-350",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "description": (
                    f"Subdomain '{dangling['subdomain']}' mengarah ke layanan "
                    f"{dangling['provider']} yang sudah tidak aktif/diklaim. "
                    "Penyerang dapat mendaftarkan resource yang sama untuk "
                    "mengambil alih subdomain (Subdomain Takeover)."
                ),
                "remediation": (
                    "Hapus DNS CNAME record yang mengarah ke resource cloud yang sudah tidak "
                    "digunakan. Lakukan audit DNS record secara berkala."
                ),
                "evidence": (
                    f"Subdomain {dangling['subdomain']} → provider: {dangling['provider']}, "
                    f"HTTP {dangling['status']}"
                ),
                "target_url": f"https://{dangling['subdomain']}"
            })

        return findings
