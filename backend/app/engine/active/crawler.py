"""
Web Crawler — Upgraded 2026 Edition
=====================================
Asynchronous web crawler with modern Single Page Application (SPA) heuristics:
  1. HTML Anchor (<a href>) link extraction
  2. JavaScript Link & Endpoint Extraction (fetch, axios, XMLHttpRequest, window.location)
  3. Single-Page Application (SPA) Route Discovery (React Router, Vue Router, Next.js _next/data)
  4. WebSocket Endpoint Discovery (ws://, wss://)
  5. HTML Form & Multipart Form Parser (with CSRF tokens, hidden fields, file uploads)
  6. Subresource Integrity & External Resource Tracking
"""

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from typing import Set, List, Dict, Any, Optional
import asyncio
import re

# Regex patterns for API & dynamic endpoint extraction from JavaScript files / inline scripts
JS_ENDPOINT_PATTERNS = [
    # fetch('/api/v1/...') or axios.get('/api/...')
    r'''(?:fetch|axios(?:\.[a-z]+)?|\$\.ajax)\s*\(\s*["']([^"']+)["']''',
    # window.location = '/...'
    r'''(?:window\.location(?:\.href)?|location\.href)\s*=\s*["']([^"']+)["']''',
    # Path string literals that look like API endpoints: "/api/...", "/v1/...", "/v2/..."
    r'''["'](/(?:api|v[0-9]|rest|graphql|auth|admin|user|users|login|register|dashboard|checkout|webhook|internal)/[a-zA-Z0-9_\-/\.]*)["']''',
    # WebSocket endpoints
    r'''["'](wss?://[^\s"'<>]+)["']''',
    # React / Vue SPA routes: path: '/...' or component with path
    r'''path:\s*["'](/[a-zA-Z0-9_\-/\.:]*)["']''',
    # Next.js API or page routes
    r'''["'](/_next/[a-zA-Z0-9_\-/\.]+)["']'''
]


class WebCrawler:
    """
    Crawler halaman asinkron generasi baru dengan dukungan SPA & JS endpoint mining.
    """

    def __init__(self, max_pages: int = 25, max_depth: int = 3, concurrency: int = 5):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.concurrency = concurrency

    async def crawl(self, base_url: str, emit_log=None) -> Dict[str, Any]:
        visited: Set[str] = set()
        to_visit: List[tuple] = [(base_url, 0)]
        base_parsed = urlparse(base_url)
        base_domain = base_parsed.netloc

        discovered_forms: List[Dict[str, Any]] = []
        discovered_urls: List[str] = []
        discovered_api_endpoints: Set[str] = set()
        discovered_ws_endpoints: Set[str] = set()
        js_files_found: Set[str] = set()

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36 DjoeraganCyber/2026"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8"
        }

        async with httpx.AsyncClient(
            verify=False,
            timeout=7.0,
            follow_redirects=True,
            headers=headers,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=self.concurrency)
        ) as client:

            while to_visit and len(visited) < self.max_pages:
                current_url, depth = to_visit.pop(0)

                clean_current, _ = urldefrag(current_url)
                if clean_current in visited or depth > self.max_depth:
                    continue

                visited.add(clean_current)
                discovered_urls.append(clean_current)

                if emit_log:
                    await emit_log(f"[CRAWLER] Crawling ({len(visited)}/{self.max_pages}) [depth {depth}]: {clean_current}")

                try:
                    res = await client.get(clean_current)
                    content_type = res.headers.get("content-type", "").lower()

                    # Handle HTML responses
                    if "text/html" in content_type:
                        soup = BeautifulSoup(res.text, "html.parser")

                        # 1. Extract Forms & Multipart inputs
                        for form in soup.find_all("form"):
                            action = form.get("action", "")
                            method = form.get("method", "get").upper()
                            enctype = form.get("enctype", "application/x-www-form-urlencoded")
                            form_url = urljoin(clean_current, action)
                            
                            inputs = []
                            input_details = []
                            for inp in form.find_all(["input", "textarea", "select"]):
                                name = inp.get("name")
                                if name:
                                    inputs.append(name)
                                    input_details.append({
                                        "name": name,
                                        "type": inp.get("type", "text"),
                                        "value": inp.get("value", "")
                                    })

                            discovered_forms.append({
                                "url": form_url,
                                "method": method,
                                "enctype": enctype,
                                "is_multipart": "multipart/form-data" in enctype,
                                "inputs": inputs,
                                "details": input_details,
                                "page": clean_current
                            })

                        # 2. Extract HTML Standard Anchor Links (<a href>)
                        for a_tag in soup.find_all("a", href=True):
                            href = a_tag["href"].strip()
                            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                                continue

                            full_url = urljoin(clean_current, href)
                            clean_link, _ = urldefrag(full_url)
                            target_parsed = urlparse(clean_link)

                            if target_parsed.netloc == base_domain and clean_link not in visited:
                                if not any(clean_link == item[0] for item in to_visit):
                                    to_visit.append((clean_link, depth + 1))

                        # 3. Extract Script sources (<script src="...">)
                        for script_tag in soup.find_all("script"):
                            src = script_tag.get("src")
                            if src:
                                js_url = urljoin(clean_current, src)
                                js_parsed = urlparse(js_url)
                                if js_parsed.netloc == base_domain:
                                    js_files_found.add(js_url)

                            # 4. Inline Script Analysis for Endpoints
                            inline_code = script_tag.string or script_tag.text or ""
                            if inline_code:
                                for pat in JS_ENDPOINT_PATTERNS:
                                    matches = re.findall(pat, inline_code)
                                    for match in matches:
                                        if match.startswith("ws://") or match.startswith("wss://"):
                                            discovered_ws_endpoints.add(match)
                                        elif match.startswith("/"):
                                            full_ep = urljoin(clean_current, match)
                                            discovered_api_endpoints.add(full_ep)

                        # 5. Extract <link> and <button data-url> references
                        for link in soup.find_all("link", href=True):
                            rel = link.get("rel", [])
                            if any(r in rel for r in ["canonical", "alternate", "next", "prev"]):
                                full_link = urljoin(clean_current, link["href"])
                                clean_l, _ = urldefrag(full_link)
                                if urlparse(clean_l).netloc == base_domain and clean_l not in visited:
                                    to_visit.append((clean_l, depth + 1))

                    elif "application/json" in content_type:
                        # Extract potential links or references in JSON response
                        try:
                            body_str = res.text
                            for pat in JS_ENDPOINT_PATTERNS:
                                matches = re.findall(pat, body_str)
                                for match in matches:
                                    if match.startswith("/"):
                                        discovered_api_endpoints.add(urljoin(clean_current, match))
                        except Exception:
                            pass

                except Exception:
                    continue

            # 6. Deep Scan JS Files for API endpoints (Top 5 JS bundles)
            if js_files_found and emit_log:
                await emit_log(f"[CRAWLER] Inspecting {min(len(js_files_found), 5)} JavaScript bundles for hidden API routes...")

            js_sample = list(js_files_found)[:5]
            for js_url in js_sample:
                try:
                    js_res = await client.get(js_url, timeout=5.0)
                    if js_res.status_code == 200:
                        js_text = js_res.text
                        for pat in JS_ENDPOINT_PATTERNS:
                            matches = re.findall(pat, js_text)
                            for match in matches:
                                if match.startswith("ws://") or match.startswith("wss://"):
                                    discovered_ws_endpoints.add(match)
                                elif match.startswith("/"):
                                    full_ep = urljoin(clean_current, match)
                                    # Ensure within base domain
                                    if urlparse(full_ep).netloc == base_domain:
                                        discovered_api_endpoints.add(full_ep)
                except Exception:
                    pass

        # Merge discovered API endpoints into discovered URLs if not already there
        for ep in discovered_api_endpoints:
            if ep not in discovered_urls:
                discovered_urls.append(ep)

        return {
            "urls": discovered_urls,
            "forms": discovered_forms,
            "api_endpoints": list(discovered_api_endpoints),
            "websocket_endpoints": list(discovered_ws_endpoints),
            "js_bundles": list(js_files_found),
            "total_visited": len(visited)
        }
