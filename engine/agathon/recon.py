"""
agathon/recon.py
────────────────────────────────────────────────────────────────────────────
Recon Intelligence Module
=========================
Performs OSINT reconnaissance on a target domain/IP using:
  - DNS enumeration (A, MX, NS, TXT, CNAME records)
  - HTTP banner grabbing (title, server header, tech stack hints)
  - Basic port scanning (common web ports)
  - Subdomain enumeration (wordlist-based)
  - Link/path enumeration via BeautifulSoup HTML parsing
  - WebLogicAuditor: Playwright-powered deep diagnostic crawl
    → Forms, XHR/fetch intercepts, tech stack fingerprinting,
      auth indicators, external resource mapping

Results are persisted to the `recon_targets` Supabase table and emitted
as a `surface_map` JSON structure for the frontend tree graph.

The run_recon() coroutine is called by the orchestrator as a BackgroundTask.

Env vars:
  SUPABASE_URL              Supabase project URL
  SUPABASE_SERVICE_ROLE_KEY Service role key
  PLAYWRIGHT_HEADLESS       "true" (default) or "false"
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger("agathon.recon")

# ── Optional DNS library ──────────────────────────────────────────────────────
try:
    import dns.resolver
    HAS_DNSPY = True
except ImportError:
    HAS_DNSPY = False
    log.warning("dnspython not installed — DNS enumeration will use socket fallback")

# ── BeautifulSoup ────────────────────────────────────────────────────────────
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    log.warning("beautifulsoup4 not installed — HTML parsing disabled")

# ── Playwright (optional, for JS-heavy targets) ───────────────────────────────
try:
    from playwright.async_api import async_playwright, BrowserContext, Page, Request
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    log.warning("playwright not installed — falling back to httpx for page fetch")


# ── Common ports to check ────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 8888, 9200, 27017]

# ── Common subdomains to bruteforce ─────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "admin", "blog",
    "app", "static", "cdn", "docs", "support", "m", "mobile",
    "login", "auth", "dashboard", "portal", "beta",
]

# ── Tech fingerprints (header / meta / script pattern → label) ───────────────
_TECH_PATTERNS: List[Tuple[str, str]] = [
    (r"next\.js|_next/", "Next.js"),
    (r"nuxt|__nuxt", "Nuxt.js"),
    (r"react|ReactDOM", "React"),
    (r"vue\.js|__vue", "Vue.js"),
    (r"angular\.min\.js|ng-version", "Angular"),
    (r"svelte", "Svelte"),
    (r"wordpress|wp-content|wp-json", "WordPress"),
    (r"drupal", "Drupal"),
    (r"shopify|myshopify", "Shopify"),
    (r"fastapi|starlette", "FastAPI"),
    (r"django", "Django"),
    (r"rails|ruby on rails", "Rails"),
    (r"laravel", "Laravel"),
    (r"express\.js|express/", "Express.js"),
    (r"graphql|/__graphql|/graphql", "GraphQL"),
    (r"supabase", "Supabase"),
    (r"firebase|firestore", "Firebase"),
    (r"cloudflare", "Cloudflare"),
    (r"vercel|\.vercel\.app", "Vercel"),
    (r"netlify", "Netlify"),
    (r"tailwind", "Tailwind CSS"),
    (r"bootstrap", "Bootstrap"),
    (r"jquery", "jQuery"),
    (r"stripe\.com/v3", "Stripe"),
    (r"recaptcha|hcaptcha", "CAPTCHA"),
    (r"sentry", "Sentry"),
    (r"segment\.com|analytics\.js", "Analytics"),
]

# ── Auth indicators (form field names / patterns) ────────────────────────────
_AUTH_PATTERNS = [
    "password", "passwd", "token", "api.?key", "secret", "auth", "credential",
    "bearer", "jwt", "session", "csrf", "login", "signin", "register", "signup",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_target(target: str) -> tuple[str, str]:
    """Return (hostname, base_url) for a given target string."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    hostname = parsed.hostname or target
    base_url = f"{parsed.scheme}://{hostname}"
    return hostname, base_url


async def _check_port(hostname: str, port: int, timeout: float = 1.5) -> bool:
    """Async TCP connect check. Returns True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _dns_records(hostname: str) -> Dict[str, List[str]]:
    """Query common DNS record types. Returns dict of type → [values]."""
    records: Dict[str, List[str]] = {}

    if HAS_DNSPY:
        for rtype in ("A", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    else:
        # Fallback: just A record via socket
        try:
            infos = socket.getaddrinfo(hostname, None)
            records["A"] = list({info[4][0] for info in infos})
        except Exception:
            pass

    return records


async def _http_banner(base_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Grab HTTP headers and page title."""
    result: Dict[str, Any] = {"url": base_url, "reachable": False}
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (ForgeGuard Recon/1.0)"},
        ) as client:
            resp = await client.get(base_url)
            result["status_code"] = resp.status_code
            result["reachable"] = True
            result["server"] = resp.headers.get("server", "")
            result["x_powered_by"] = resp.headers.get("x-powered-by", "")
            result["content_type"] = resp.headers.get("content-type", "")
            result["redirect_url"] = str(resp.url) if str(resp.url) != base_url else None

            if HAS_BS4 and "html" in result.get("content_type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                title_tag = soup.find("title")
                result["title"] = title_tag.get_text(strip=True)[:200] if title_tag else ""
                # Extract meta generator
                gen = soup.find("meta", attrs={"name": "generator"})
                result["generator"] = gen.get("content", "")[:100] if gen else ""
                # Count links
                result["link_count"] = len(soup.find_all("a", href=True))
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


async def _playwright_fetch(url: str) -> Dict[str, Any]:
    """Fetch a JS-rendered page with Playwright for richer enumeration."""
    if not HAS_PLAYWRIGHT:
        return {}
    result: Dict[str, Any] = {}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page()
            await page.goto(url, timeout=20000, wait_until="networkidle")
            result["title"] = await page.title()
            result["links"] = await page.eval_on_selector_all(
                "a[href]", "els => els.slice(0,50).map(e => e.href)"
            )
            await browser.close()
    except Exception as e:
        result["playwright_error"] = str(e)[:200]
    return result


async def _subdomain_bruteforce(hostname: str) -> List[str]:
    """Check common subdomains via DNS."""
    found: List[str] = []
    # Strip leading www if present
    base = hostname.lstrip("www.") if hostname.startswith("www.") else hostname

    async def check(sub: str) -> Optional[str]:
        candidate = f"{sub}.{base}"
        try:
            if HAS_DNSPY:
                dns.resolver.resolve(candidate, "A", lifetime=3)
            else:
                socket.getaddrinfo(candidate, None)
            return candidate
        except Exception:
            return None

    tasks = [check(sub) for sub in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, str):
            found.append(r)
    return found


# ─────────────────────────────────────────────────────────────────────────────
# WebLogicAuditor — Playwright Diagnostic Crawl
# ─────────────────────────────────────────────────────────────────────────────

class WebLogicAuditor:
    """
    Playwright-powered diagnostic crawl for deep web-application surface mapping.

    Inspects the fully JS-rendered page and intercepts network traffic to extract:
      - HTML forms (action URL, method, field names, auth indicators)
      - API/XHR/fetch endpoints called during page load and interaction
      - External resources (CDN scripts, fonts, analytics)
      - Tech stack fingerprints (framework, backend, services)
      - Auth indicators (login forms, token patterns, CSRF fields)
      - Internal path enumeration (links found in rendered DOM)

    Returns a dict with:
      - ``forms``          — list of form metadata dicts
      - ``api_calls``      — list of unique XHR/fetch URL strings
      - ``external_scripts`` — list of external script src URLs
      - ``tech_stack``     — list of detected technology strings
      - ``auth_found``     — bool, True if auth-related indicators found
      - ``internal_paths`` — list of internal href strings (≤ 30)
      - ``nodes``          — list of SurfaceMap-compatible node dicts
                             (append directly to surface_map["nodes"])

    Usage::

        auditor = WebLogicAuditor(url="https://example.com")
        data = await auditor.audit()
        surface_map["nodes"].extend(data["nodes"])
        surface_map["root_children"].append("weblogic")
    """

    # Playwright launch args — Railway has no /dev/shm
    _LAUNCH_ARGS = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--single-process",
    ]

    def __init__(
        self,
        url: str,
        headless: bool = True,
        timeout: int = 25000,
        max_api_calls: int = 40,
        max_paths: int = 30,
    ) -> None:
        self.url = url
        self.headless = headless
        self.timeout = timeout
        self.max_api_calls = max_api_calls
        self.max_paths = max_paths
        self._origin = urlparse(url).scheme + "://" + (urlparse(url).hostname or "")

    # ── Internal helpers ──────────────────────────────────────────────────

    def _is_internal(self, url: str) -> bool:
        return url.startswith(self._origin) or url.startswith("/")

    def _is_api_like(self, url: str) -> bool:
        """Heuristic: classify a request URL as an API/data call."""
        lower = url.lower()
        api_patterns = [
            "/api/", "/graphql", "/v1/", "/v2/", "/v3/",
            ".json", "format=json", "content-type=application",
            "/rpc", "/rest/", "/data/", "/query",
        ]
        return any(p in lower for p in api_patterns)

    def _detect_tech(self, content: str) -> List[str]:
        """Fingerprint technologies from page source / network traffic."""
        detected: List[str] = []
        seen: set = set()
        content_lower = content.lower()
        for pattern, label in _TECH_PATTERNS:
            if label not in seen and re.search(pattern, content_lower, re.IGNORECASE):
                detected.append(label)
                seen.add(label)
        return detected

    def _check_auth_indicators(self, content: str) -> bool:
        """Return True if the page content has auth-related patterns."""
        content_lower = content.lower()
        return any(re.search(p, content_lower) for p in _AUTH_PATTERNS)

    # ── Node builders ─────────────────────────────────────────────────────

    def _build_nodes(
        self,
        forms: List[Dict[str, Any]],
        api_calls: List[str],
        external_scripts: List[str],
        tech_stack: List[str],
        auth_found: bool,
        internal_paths: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Construct SurfaceNode-compatible dicts for the /dashboard/recon tree.
        Structure mirrors the existing surface map format:
          { id, label, type, children: [child_id, ...] }
        """
        nodes: List[Dict[str, Any]] = []

        # ── Forms branch ─────────────────────────────────────────────────
        form_children: List[str] = []
        for i, form in enumerate(forms[:6]):
            nid = f"form_{i}"
            method = form.get("method", "GET").upper()
            action = form.get("action", "/")[:40]
            label = f"{method} {action}"
            field_children: List[str] = []

            # Form fields as leaf nodes
            for j, field in enumerate(form.get("fields", [])[:5]):
                fnid = f"form_{i}_field_{j}"
                is_sensitive = any(
                    re.search(p, field.get("name", ""), re.I) for p in _AUTH_PATTERNS
                )
                flabel = f"{'⚠ ' if is_sensitive else ''}{field.get('type','text')}: {field.get('name','')[:25]}"
                nodes.append({
                    "id": fnid,
                    "label": flabel,
                    "type": "auth_field" if is_sensitive else "record",
                    "children": [],
                })
                field_children.append(fnid)

            nodes.append({
                "id": nid,
                "label": label[:40],
                "type": "form",
                "children": field_children,
            })
            form_children.append(nid)

        if form_children:
            auth_icon = "⚠ " if auth_found else ""
            nodes.append({
                "id": "weblogic_forms",
                "label": f"{auth_icon}Forms ({len(forms)})",
                "type": "forms",
                "children": form_children,
            })

        # ── API calls branch ──────────────────────────────────────────────
        api_children: List[str] = []
        for i, call_url in enumerate(api_calls[:12]):
            nid = f"apicall_{i}"
            parsed = urlparse(call_url)
            label = (parsed.path or call_url)[:40]
            nodes.append({"id": nid, "label": label, "type": "js_endpoint", "children": []})
            api_children.append(nid)

        if api_children:
            nodes.append({
                "id": "weblogic_api",
                "label": f"API Calls ({len(api_calls)})",
                "type": "js_endpoints",
                "children": api_children,
            })

        # ── Tech stack branch ─────────────────────────────────────────────
        tech_children: List[str] = []
        for i, tech in enumerate(tech_stack[:10]):
            nid = f"tech_{i}"
            nodes.append({"id": nid, "label": tech, "type": "tech_item", "children": []})
            tech_children.append(nid)

        if tech_children:
            nodes.append({
                "id": "weblogic_tech",
                "label": f"Tech Stack ({len(tech_stack)})",
                "type": "tech",
                "children": tech_children,
            })

        # ── External scripts branch ───────────────────────────────────────
        ext_children: List[str] = []
        for i, src in enumerate(external_scripts[:8]):
            nid = f"ext_{i}"
            parsed = urlparse(src)
            label = (parsed.hostname or src)[:40]
            nodes.append({"id": nid, "label": label, "type": "record", "children": []})
            ext_children.append(nid)

        if ext_children:
            nodes.append({
                "id": "weblogic_ext",
                "label": f"External ({len(external_scripts)})",
                "type": "external",
                "children": ext_children,
            })

        # ── WebLogic root branch ──────────────────────────────────────────
        wl_children: List[str] = []
        if form_children:
            wl_children.append("weblogic_forms")
        if api_children:
            wl_children.append("weblogic_api")
        if tech_children:
            wl_children.append("weblogic_tech")
        if ext_children:
            wl_children.append("weblogic_ext")

        nodes.append({
            "id": "weblogic",
            "label": "App Logic Audit",
            "type": "weblogic",
            "children": wl_children,
        })

        return nodes

    # ── Main entrypoint ───────────────────────────────────────────────────

    async def audit(self) -> Dict[str, Any]:
        """
        Run the full Playwright diagnostic crawl.

        Returns:
            dict with keys:
              forms, api_calls, external_scripts, tech_stack,
              auth_found, internal_paths, nodes
        """
        if not HAS_PLAYWRIGHT:
            log.warning("WebLogicAuditor: playwright unavailable — returning empty audit")
            return {
                "forms": [], "api_calls": [], "external_scripts": [],
                "tech_stack": [], "auth_found": False, "internal_paths": [],
                "nodes": [], "error": "playwright not installed",
            }

        forms: List[Dict[str, Any]] = []
        api_calls: List[str] = []
        external_scripts: List[str] = []
        all_content_pieces: List[str] = []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=self.headless,
                    args=self._LAUNCH_ARGS,
                )
                ctx: BrowserContext = await browser.new_context(
                    user_agent="Mozilla/5.0 (ForgeGuard WebLogicAuditor/2.0) Gecko/20100101 Firefox/115.0",
                    ignore_https_errors=True,
                )

                # ── Intercept network requests ────────────────────────────
                intercepted_urls: set[str] = set()
                ext_script_set: set[str] = set()

                async def on_request(req: Request) -> None:
                    req_url = req.url
                    # XHR/fetch API calls
                    if req.resource_type in ("xhr", "fetch") and len(api_calls) < self.max_api_calls:
                        if req_url not in intercepted_urls:
                            api_calls.append(req_url)
                            intercepted_urls.add(req_url)
                    # External scripts (different origin)
                    if req.resource_type == "script" and not self._is_internal(req_url):
                        ext_script_set.add(req_url)
                    # Collect URL fragments for tech detection
                    all_content_pieces.append(req_url)

                page: Page = await ctx.new_page()
                page.on("request", on_request)

                # ── Navigate to target ────────────────────────────────────
                log.info(f"[WebLogicAuditor] Navigating to {self.url}")
                try:
                    await page.goto(
                        self.url,
                        timeout=self.timeout,
                        wait_until="networkidle",
                    )
                except Exception as nav_err:
                    log.warning(f"[WebLogicAuditor] Navigation warning: {nav_err}")
                    # Don't abort — partial results are still useful

                # ── Extract page source for fingerprinting ────────────────
                try:
                    page_content = await page.content()
                    all_content_pieces.append(page_content)
                except Exception:
                    page_content = ""

                # ── Extract forms ─────────────────────────────────────────
                try:
                    raw_forms = await page.eval_on_selector_all(
                        "form",
                        """forms => forms.map(f => ({
                            action: f.action || f.getAttribute('action') || '',
                            method: f.method || f.getAttribute('method') || 'GET',
                            fields: Array.from(f.querySelectorAll('input,select,textarea')).slice(0,10).map(el => ({
                                type: el.type || el.tagName.toLowerCase(),
                                name: el.name || el.id || '',
                                placeholder: el.placeholder || '',
                            }))
                        }))""",
                    )
                    forms = raw_forms[:8]
                except Exception as form_err:
                    log.warning(f"[WebLogicAuditor] Form extraction error: {form_err}")

                # ── Extract internal paths ────────────────────────────────
                try:
                    raw_links: List[str] = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.slice(0,60).map(e => e.href)",
                    )
                    internal_paths = list({
                        u for u in raw_links
                        if self._is_internal(u) and u != self.url and u != self._origin + "/"
                    })[:self.max_paths]
                except Exception:
                    internal_paths = []

                await browser.close()

        except Exception as e:
            log.exception(f"[WebLogicAuditor] Critical error: {e}")
            return {
                "forms": [], "api_calls": api_calls, "external_scripts": [],
                "tech_stack": [], "auth_found": False, "internal_paths": [],
                "nodes": [], "error": str(e)[:300],
            }

        # ── Post-process ──────────────────────────────────────────────────
        combined_content = " ".join(all_content_pieces)
        tech_stack = self._detect_tech(combined_content)
        auth_found = self._check_auth_indicators(combined_content)

        # Deduplicate and clean API calls — keep only API-like endpoints
        api_calls_clean = list(dict.fromkeys(
            u for u in api_calls if self._is_api_like(u)
        ))[:self.max_api_calls]

        external_scripts = sorted(ext_script_set)[:20]

        # Build surface-map-compatible nodes
        nodes = self._build_nodes(
            forms=forms,
            api_calls=api_calls_clean,
            external_scripts=external_scripts,
            tech_stack=tech_stack,
            auth_found=auth_found,
            internal_paths=internal_paths,
        )

        log.info(
            f"[WebLogicAuditor] Done — {len(forms)} forms, {len(api_calls_clean)} API calls, "
            f"{len(tech_stack)} tech, {len(external_scripts)} ext scripts"
        )

        return {
            "forms": forms,
            "api_calls": api_calls_clean,
            "external_scripts": external_scripts,
            "tech_stack": tech_stack,
            "auth_found": auth_found,
            "internal_paths": internal_paths,
            "nodes": nodes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Surface map builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_surface_map(
    hostname: str,
    dns_records: Dict[str, List[str]],
    banner: Dict[str, Any],
    open_ports: List[int],
    subdomains: List[str],
    weblogic_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the tree-graph JSON for the frontend."""
    nodes = []

    # DNS node
    dns_children = []
    for rtype, vals in dns_records.items():
        for val in vals[:3]:  # cap at 3 per type
            node_id = f"dns_{rtype}_{val[:20].replace(' ', '_')}"
            nodes.append({
                "id": node_id,
                "label": f"{rtype}: {val[:40]}",
                "type": "record",
                "children": [],
            })
            dns_children.append(node_id)
    nodes.append({"id": "dns", "label": "DNS Records", "type": "dns", "children": dns_children})

    # HTTP node
    http_children = []
    if banner.get("reachable"):
        if banner.get("title"):
            nodes.append({"id": "http_title", "label": f"Title: {banner['title'][:40]}", "type": "record", "children": []})
            http_children.append("http_title")
        if banner.get("server"):
            nodes.append({"id": "http_server", "label": f"Server: {banner['server'][:40]}", "type": "record", "children": []})
            http_children.append("http_server")
        if banner.get("status_code"):
            nodes.append({"id": "http_status", "label": f"HTTP {banner['status_code']}", "type": "record", "children": []})
            http_children.append("http_status")
    nodes.append({"id": "http", "label": "HTTP Banner", "type": "http", "children": http_children})

    # Ports node
    port_children = []
    for port in open_ports:
        nid = f"port_{port}"
        label = {80: "HTTP :80", 443: "HTTPS :443", 22: "SSH :22", 21: "FTP :21",
                 3306: "MySQL :3306", 5432: "Postgres :5432", 6379: "Redis :6379",
                 8080: "Alt-HTTP :8080", 9200: "Elastic :9200"}.get(port, f"TCP :{port}")
        nodes.append({"id": nid, "label": label, "type": "port", "children": []})
        port_children.append(nid)
    nodes.append({"id": "ports", "label": f"Open Ports ({len(open_ports)})", "type": "ports", "children": port_children})

    # Subdomains node
    sub_children = []
    for sub in subdomains[:8]:
        nid = f"sub_{sub.replace('.', '_')}"
        nodes.append({"id": nid, "label": sub, "type": "subdomain", "children": []})
        sub_children.append(nid)
    if subdomains:
        nodes.append({"id": "subdomains", "label": f"Subdomains ({len(subdomains)})", "type": "subdomains", "children": sub_children})

    # Root children
    root_children = ["dns", "http", "ports"]
    if subdomains:
        root_children.append("subdomains")

    # WebLogicAuditor nodes (depth >= 3)
    if weblogic_data and weblogic_data.get("nodes"):
        nodes.extend(weblogic_data["nodes"])
        root_children.append("weblogic")

    meta: Dict[str, Any] = {
        "dns_records": len(dns_records),
        "open_ports": open_ports,
        "subdomains_found": len(subdomains),
        "http_reachable": banner.get("reachable", False),
    }
    if weblogic_data:
        meta["weblogic"] = {
            "forms": len(weblogic_data.get("forms", [])),
            "api_calls": len(weblogic_data.get("api_calls", [])),
            "tech_stack": weblogic_data.get("tech_stack", []),
            "auth_found": weblogic_data.get("auth_found", False),
        }

    return {
        "root": hostname,
        "nodes": nodes,
        "root_children": root_children,
        "meta": meta,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main entrypoint — called as BackgroundTask from orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def run_recon(
    recon_id: str,
    target: str,
    depth: int,
    supabase_admin: Any,
) -> None:
    """
    Background recon task. Updates the recon_targets row with results.

    Args:
        recon_id:       UUID of the recon_targets row
        target:         Domain, IP, or URL to scan
        depth:          Scan depth (1=fast, 2=normal, 3=deep+WebLogicAuditor)
        supabase_admin: Admin Supabase client (bypasses RLS)
    """
    log.info(f"[recon:{recon_id[:8]}] Starting recon on {target!r} depth={depth}")

    # Mark as running
    supabase_admin.table("recon_targets").update({
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", recon_id).execute()

    try:
        hostname, base_url = _normalize_target(target)

        # Phase 1: DNS + HTTP (always)
        dns_task = _dns_records(hostname)
        banner_task = _http_banner(base_url)
        dns_records, banner = await asyncio.gather(dns_task, banner_task)

        # Phase 2: Port scan (depth >= 1)
        ports_to_check = COMMON_PORTS if depth >= 2 else [80, 443, 22, 8080]
        port_tasks = [_check_port(hostname, p) for p in ports_to_check]
        port_results = await asyncio.gather(*port_tasks, return_exceptions=True)
        open_ports = [
            ports_to_check[i]
            for i, r in enumerate(port_results)
            if r is True
        ]

        # Phase 3: Subdomain bruteforce (depth >= 2)
        subdomains: List[str] = []
        if depth >= 2:
            subdomains = await _subdomain_bruteforce(hostname)

        # Phase 4: WebLogicAuditor deep crawl (depth >= 3)
        weblogic_data: Optional[Dict[str, Any]] = None
        if depth >= 3 and HAS_PLAYWRIGHT:
            log.info(f"[recon:{recon_id[:8]}] Launching WebLogicAuditor on {base_url}")
            auditor = WebLogicAuditor(url=base_url)
            weblogic_data = await auditor.audit()

            # Also merge Playwright-found links into banner for link_count
            if weblogic_data.get("internal_paths"):
                banner["links"] = weblogic_data["internal_paths"]

        surface_map = _build_surface_map(
            hostname, dns_records, banner, open_ports, subdomains, weblogic_data
        )

        # Persist results
        supabase_admin.table("recon_targets").update({
            "status": "done",
            "surface_map": surface_map,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", recon_id).execute()

        log.info(
            f"[recon:{recon_id[:8]}] Done — "
            f"{len(dns_records)} DNS types, {len(open_ports)} open ports, "
            f"{len(subdomains)} subdomains"
            + (f", {len(weblogic_data.get('tech_stack', []))} tech detected" if weblogic_data else "")
        )

    except Exception as exc:
        log.exception(f"[recon:{recon_id[:8]}] Failed: {exc}")
        supabase_admin.table("recon_targets").update({
            "status": "failed",
            "error_msg": str(exc)[:500],
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", recon_id).execute()
