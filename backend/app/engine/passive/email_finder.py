import asyncio
import re
import subprocess
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Set, Optional
import httpx
from bs4 import BeautifulSoup

EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

EXCLUDED_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
    '.js', '.css', '.woff', '.woff2', '.ttf', '.eot', '.json',
    '.map', '.ts', '.jsx', '.tsx'
}

EXCLUDED_PREFIXES = {
    'example', 'sample', 'test', 'user', 'dummy', 'yourname',
    'support@yourdomain', 'info@yourdomain', 'name@domain'
}

EXCLUDED_PACKAGES = {
    'slick-carousel', 'core-js', 'jquery', 'bootstrap', 'webpack',
    'babel', 'vue', 'react', 'angular', 'lodash'
}

HOSTING_PROVIDER_DOMAINS = {
    'cloudflare.com', 'rumahweb.com', 'rumahweb.co.id', 'godaddy.com',
    'hostinger.com', 'hostinger.co.id', 'niagahoster.co.id', 'idwebhost.com',
    'qwords.com', 'domainesia.com', 'jagoanhosting.com', 'domaincontrol.com',
    'registrar-servers.com', 'name-services.com', 'awsdns', 'akamai.com',
    'digitalocean.com', 'linode.com', 'vultr.com', 'ovh.net', 'hetzner.com'
}


def extract_clean_domain(hostname: str) -> str:
    """Bersihkan www. atau sub-prefix umum untuk root domain."""
    h = hostname.lower().strip()
    if h.startswith('www.'):
        return h[4:]
    return h


class TargetEmailDetector:
    """
    Engine intelijen kontak otomatis untuk mendeteksi alamat email resmi,
    email security.txt (RFC 9116), alamat Gmail bisnis/kontak,
    serta integrasi Google Workspace MX dari target website.
    """

    @staticmethod
    def _is_valid_email(email: str) -> bool:
        if not email or '@' not in email:
            return False
        email_lower = email.lower().strip()
        parts = email_lower.split('@')
        if len(parts) != 2:
            return False
        local, domain = parts
        if not local or not domain:
            return False
        if any(email_lower.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
            return False
        if any(pkg in email_lower for pkg in EXCLUDED_PACKAGES):
            return False
        if any(email_lower.startswith(pref) for pref in EXCLUDED_PREFIXES):
            return False
        if domain in ('example.com', 'domain.com', 'yoursite.com', 'target-website.com'):
            return False
        return True

    @staticmethod
    def _check_dns_mx(domain: str) -> Dict[str, Any]:
        """Periksa DNS MX untuk mendeteksi apakah domain menggunakan Google Workspace / Gmail MX."""
        is_google = False
        mx_records = []
        try:
            out = subprocess.check_output(
                f'nslookup -type=MX {domain}',
                shell=True,
                stderr=subprocess.DEVNULL,
                timeout=3
            ).decode(errors='ignore')
            for line in out.splitlines():
                if 'mail exchanger' in line.lower() or 'mx preference' in line.lower():
                    mx_records.append(line.strip())
                    if any(g in line.lower() for g in ['google', 'googlemail', 'aspmx', 'l.google.com']):
                        is_google = True
        except Exception:
            pass
        return {
            "is_google_workspace": is_google,
            "mx_records": mx_records[:3]
        }

    @staticmethod
    def _check_dns_soa(domain: str) -> Optional[str]:
        """Ekstraksi alamat email administrator dari DNS SOA Record."""
        try:
            out = subprocess.check_output(
                f'nslookup -type=SOA {domain}',
                shell=True,
                stderr=subprocess.DEVNULL,
                timeout=3
            ).decode(errors='ignore')
            for line in out.splitlines():
                if 'responsible mail' in line.lower() or 'mail addr' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        raw_rname = parts[1].strip()
                        rparts = raw_rname.split('.', 1)
                        if len(rparts) == 2:
                            rname_email = f"{rparts[0]}@{rparts[1]}".rstrip('.')
                            if TargetEmailDetector._is_valid_email(rname_email):
                                return rname_email
        except Exception:
            pass
        return None

    @classmethod
    async def detect(cls, target_url: str) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.netloc or target_url
        hostname = hostname.lower().strip()
        clean_domain = extract_clean_domain(hostname)
        scheme = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
        base_url = f"{scheme}://{hostname}"

        detected_emails: Set[str] = set()
        security_txt_emails: Set[str] = set()
        website_scraped_emails: Set[str] = set()
        contact_pages_found: List[str] = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DjoeraganCyber-Audit/2026",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True, headers=headers) as client:
            # 1. Probe RFC 9116 security.txt
            for path in ['/.well-known/security.txt', '/security.txt']:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200:
                        matches = EMAIL_REGEX.findall(resp.text)
                        for m in matches:
                            if cls._is_valid_email(m):
                                security_txt_emails.add(m.lower().strip())
                except Exception:
                    pass

            # 2. Probe Landing Page & mailto links
            try:
                resp = await client.get(base_url)
                if resp.status_code == 200:
                    landing_html = resp.text
                    matches = EMAIL_REGEX.findall(landing_html)
                    for m in matches:
                        if cls._is_valid_email(m):
                            website_scraped_emails.add(m.lower().strip())

                    soup = BeautifulSoup(landing_html, "html.parser")
                    for a in soup.find_all("a", href=True):
                        href = a["href"].strip()
                        if href.lower().startswith("mailto:"):
                            clean_mail = href[7:].split("?")[0].strip().lower()
                            if cls._is_valid_email(clean_mail):
                                website_scraped_emails.add(clean_mail)
                        elif any(k in href.lower() for k in ["kontak", "contact", "hubungi", "about", "tentang", "help"]):
                            full_sub = urljoin(base_url, href)
                            if full_sub not in contact_pages_found and len(contact_pages_found) < 3:
                                contact_pages_found.append(full_sub)
            except Exception:
                pass

            # 3. Probe secondary contact pages jika ada
            for page_url in contact_pages_found:
                try:
                    resp = await client.get(page_url)
                    if resp.status_code == 200:
                        matches = EMAIL_REGEX.findall(resp.text)
                        for m in matches:
                            if cls._is_valid_email(m):
                                website_scraped_emails.add(m.lower().strip())
                        soup = BeautifulSoup(resp.text, "html.parser")
                        for a in soup.find_all("a", href=True):
                            href = a["href"].strip()
                            if href.lower().startswith("mailto:"):
                                clean_mail = href[7:].split("?")[0].strip().lower()
                                if cls._is_valid_email(clean_mail):
                                    website_scraped_emails.add(clean_mail)
                except Exception:
                    pass

        detected_emails.update(security_txt_emails)
        detected_emails.update(website_scraped_emails)

        # 4. Check DNS MX (Google Workspace) & SOA Admin email
        loop = asyncio.get_event_loop()
        dns_mx_info = await loop.run_in_executor(None, cls._check_dns_mx, clean_domain)
        dns_soa_email = await loop.run_in_executor(None, cls._check_dns_soa, clean_domain)
        if dns_soa_email and cls._is_valid_email(dns_soa_email):
            detected_emails.add(dns_soa_email.lower())

        # Categorize Gmail addresses found
        gmail_addresses = [e for e in detected_emails if e.endswith('@gmail.com') or e.endswith('@googlemail.com')]
        has_gmail = len(gmail_addresses) > 0 or dns_mx_info["is_google_workspace"]

        # Filter out 3rd-party hosting provider emails from being the primary recipient
        legit_detected = [
            e for e in detected_emails
            if not any(hp in e.split('@')[-1] for hp in HOSTING_PROVIDER_DOMAINS)
        ]

        # 5. Determine Primary Email & Source
        primary_email = ""
        source = "domain_standard"
        source_label = f"Standar Domain Keamanan (@{clean_domain})"

        if security_txt_emails:
            primary_email = sorted(list(security_txt_emails))[0]
            source = "security_txt"
            source_label = "File Standar Keamanan RFC 9116 (security.txt)"
        elif gmail_addresses:
            # Website explicitly lists a @gmail.com contact
            primary_email = gmail_addresses[0]
            source = "website_gmail"
            source_label = "Akun Gmail Resmi yang Tertera di Website"
        elif legit_detected:
            # Prioritize email with matching domain
            domain_specific = [e for e in legit_detected if clean_domain in e]
            if domain_specific:
                primary_email = domain_specific[0]
            else:
                primary_email = sorted(legit_detected)[0]
            source = "website_html"
            source_label = "Email Kontak Terdeteksi di Halaman Website"
        else:
            primary_email = f"security@{clean_domain}"
            source = "domain_standard"
            source_label = f"Standar Domain Keamanan (@{clean_domain})"

        # 6. Build Candidate Suggestions List
        standard_fallbacks = [
            f"security@{clean_domain}",
            f"admin@{clean_domain}",
            f"info@{clean_domain}",
            f"contact@{clean_domain}"
        ]
        
        all_candidates: List[str] = []
        if primary_email and primary_email not in all_candidates:
            all_candidates.append(primary_email)
        for e in sorted(list(detected_emails)):
            if e not in all_candidates:
                all_candidates.append(e)
        for f in standard_fallbacks:
            if f not in all_candidates:
                all_candidates.append(f)

        return {
            "target_url": target_url,
            "target_hostname": clean_domain,
            "primary_email": primary_email,
            "detected_emails": sorted(list(detected_emails)),
            "all_suggestions": all_candidates[:6],
            "has_gmail": has_gmail,
            "gmail_addresses": gmail_addresses,
            "is_google_workspace": dns_mx_info["is_google_workspace"],
            "source": source,
            "source_label": source_label
        }
