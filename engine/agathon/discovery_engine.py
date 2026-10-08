"""
ForgeGuard AI — Discovery Engine
Passive + Active diagnostic crawl via Playwright.
Maps technical hierarchy, extracts input vectors (forms/fields),
and harvests API endpoint paths from client-side scripts & network traffic.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Optional, Set, Dict, List, Pattern
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Route, Request as PWRequest


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class InputVector:
    """A single user-controllable input discovered on a page."""
    element_type: str          # "input", "textarea", "select", "hidden"
    name: str
    id: str
    placeholder: str
    tag: str                  # HTML tag name
    form_action: str          # parent <form> action URL
    form_method: str          # GET / POST
    css_selector: str
    page_url: str


@dataclass
class ApiEndpoint:
    """An API endpoint path extracted from JS or network traffic."""
    url: str
    method: str               # GET | POST | PUT | DELETE | PATCH
    source: str               # "network" | "script_static" | "script_inline"
    origin_page: str
    content_type: str
    status_code: int
    request_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class PageNode:
    """Node in the crawl hierarchy tree."""
    url: str
    depth: int
    title: str
    status: int
    input_vectors: List[InputVector] = field(default_factory=list)
    api_endpoints: List[ApiEndpoint] = field(default_factory=list)
    children: List[str] = field(default_factory=list)  # child URLs
    scripts: List[str] = field(default_factory=list)
    content_hash: str = ""


@dataclass
class DiscoveryReport:
    """Top-level report emitted by DiscoveryEngine."""
    target: str
    base_domain: str
    total_pages: int
    total_input_vectors: int
    total_api_endpoints: int
    hierarchy: Dict[str, PageNode]
    input_vector_catalogue: List[InputVector]
    api_endpoint_catalogue: List[ApiEndpoint]
    crawl_errors: List[Dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DiscoveryEngine:
    """
    Asynchronous Playwright crawler that performs passive (network-harvest)
    and active (DOM-walk) diagnostics of a target URL.
    """

    # Patterns for JS endpoint extraction
    ENDPOINT_PATTERNS: List[Pattern] = [
        # fetch / axios-style
        re.compile(r"""fetch\s*\(\s*["'`](/[^"'`\s]+)["'`]""", re.IGNORECASE),
        # path strings with common API segments
        re.compile(r"""["'`](/api/v?\d*/[a-zA-Z0-9_\-/.]+)["'`]"""),
        # window.location assignments
        re.compile(r"""window\.location\s*=\s*["'`]([^"'`]+)["'`]"""),
        # XMLHttpRequest .open
        re.compile(r"""\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
        # route patterns in React Router / Vue Router
        re.compile(r"""path\s*:\s*["'`](/[a-zA-Z0-9_\-/:]+)["'`]"""),
        # base URL construction
        re.compile(r"""baseURL\s*[:=]\s*["'`]([^"'`]+)["'`]"""),
    ]

    def __init__(
        self,
        *,
        headless: bool = True,
        max_depth: int = 5,
        max_pages: int = 500,
        respect_robots: bool = True,
        user_agent: str = "ForgeGuard-SecurityScanner/2.0",
        request_timeout: int = 25_000,
        allowed_domains: Optional[Set[str]] = None,
        concurrency: int = 8,
        auth_token: Optional[str] = None,
        proxy: Optional[Dict[str, str]] = None,
    ):
        self.headless = headless
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.request_timeout = request_timeout
        self.allowed_domains = allowed_domains or set()
        self.concurrency = concurrency
        self.auth_token = auth_token
        self.proxy = proxy

        # Internal state
        self._visited: Set[str] = set()
        self._pages: Dict[str, PageNode] = {}
        self._input_vectors: List[InputVector] = []
        self._api_endpoints: List[ApiEndpoint] = []
        self._crawl_errors: List[Dict] = []
        self._queue: asyncio.Queue = asyncio.Queue()
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(concurrency)
        self._lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self, target_url: str) -> DiscoveryReport:
        """Entry point: crawl *target_url* and return a DiscoveryReport."""
        parsed = urlparse(target_url)
        base_domain = parsed.netloc
        if not self.allowed_domains:
            self.allowed_domains = {base_domain}

        await self._queue.put((target_url, 0))

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.headless,
                proxy=self.proxy or None,
                args=["--disable-blink-features=AutomationControlled",
                      "--no-sandbox",
                      "--disable-dev-shm-usage"],
            )
            context = await self._build_context(browser)
            try:
                workers = [
                    asyncio.create_task(self._worker(context, base_domain))
                    for _ in range(self.concurrency)
                ]
                # Wait until queue is drained and all workers idle
                await self._queue.join()
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
            finally:
                await context.close()
                await browser.close()

        return self._build_report(target_url, base_domain)

    # ------------------------------------------------------------------
    # Internals — Browser Setup
    # ------------------------------------------------------------------

    async def _build_context(self, browser: Browser) -> BrowserContext:
        context = await browser.new_context(
            user_agent=self.user_agent,
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
            locale="en-US",
        )
        if self.auth_token:
            # Inject auth cookie for authenticated crawling
            await context.add_cookies([{
                "name": "Authorization",
                "value": self.auth_token,
                "domain": list(self.allowed_domains)[0],
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            }])
        return context

    # ------------------------------------------------------------------
    # Internals — Worker Loop
    # ------------------------------------------------------------------

    async def _worker(self, context: BrowserContext, base_domain: str) -> None:
        while True:
            try:
                url, depth = await self._queue.get()
            except asyncio.CancelledError:
                return

            async with self._semaphore:
                try:
                    await self._process_page(context, url, depth, base_domain)
                except Exception as exc:
                    async with self._lock:
                        self._crawl_errors.append({"url": url, "error": str(exc)})
                finally:
                    self._queue.task_done()

    # ------------------------------------------------------------------
    # Internals — Page Processing
    # ------------------------------------------------------------------

    async def _process_page(
        self, context: BrowserContext, url: str, depth: int, base_domain: str
    ) -> None:
        # Deduplicate
        url_norm = self._normalise(url)
        async with self._lock:
            if url_norm in self._visited or len(self._visited) >= self.max_pages:
                return
            self._visited.add(url_norm)

        page = await context.new_page()
        network_calls: List[Dict] = []
        response_info: Dict = {}

        # --- Hook network traffic ---
        async def _route_handler(route: Route):
            req: PWRequest = route.request
            if req.resource_type in ("xhr", "fetch", "script"):
                network_calls.append({
                    "url": req.url,
                    "method": req.method,
                    "headers": dict(req.headers),
                    "resource_type": req.resource_type,
                })
            await route.continue_()

        await page.route("**/*", _route_handler)

        try:
            resp = await page.goto(url, timeout=self.request_timeout, wait_until="domcontentloaded")
            if resp:
                response_info = {
                    "status": resp.status,
                    "content_type": resp.headers.get("content-type", ""),
                }
            # Let JS-heavy pages settle
            await asyncio.sleep(0.8)

            # ---- Passive harvest: network endpoints ----
            api_endpoints = self._harvest_network_endpoints(network_calls, url, response_info)

            # ---- Active: DOM walk ----
            input_vectors = await self._extract_input_vectors(page, url)
            script_endpoints = await self._extract_script_endpoints(page, url)
            all_endpoints = api_endpoints + script_endpoints

            # ---- Build page node ----
            title = await page.title()
            content = await page.content()
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            node = PageNode(
                url=url,
                depth=depth,
                title=title,
                status=response_info.get("status", 0),
                input_vectors=input_vectors,
                api_endpoints=all_endpoints,
                content_hash=content_hash,
            )

            async with self._lock:
                self._pages[url] = node
                self._input_vectors.extend(input_vectors)
                self._api_endpoints.extend(all_endpoints)

            # ---- Enqueue same-domain links ----
            if depth < self.max_depth:
                links = await self._extract_internal_links(page, base_domain)
                node.children = [self._normalise(l) for l in links]
                for link in links:
                    n_link = self._normalise(link)
                    async with self._lock:
                        if n_link not in self._visited:
                            await self._queue.put((link, depth + 1))

        except Exception:
            raise
        finally:
            await page.close()

    # ------------------------------------------------------------------
    # Active: Input Vector Extraction
    # ------------------------------------------------------------------

    async def _extract_input_vectors(self, page: Page, page_url: str) -> List[InputVector]:
        vectors: List[InputVector] = []
        # Gather all form elements
        forms = await page.evaluate("""
            () => {
                const results = [];
                document.querySelectorAll('form').forEach(form => {
                    const action = form.action || window.location.href;
                    const method = (form.method || 'GET').toUpperCase();
                    form.querySelectorAll('input, textarea, select, button').forEach(el => {
                        const rect = el.getBoundingClientRect();
                        results.push({
                            tag: el.tagName.toLowerCase(),
                            type: el.type || '',
                            name: el.name || '',
                            id: el.id || '',
                            placeholder: el.placeholder || '',
                            formAction: action,
                            formMethod: method,
                            visible: rect.width > 0 && rect.height > 0,
                            selector: (el.id ? '#' + el.id : '') ||
                                      (el.name ? '[name="' + el.name + '"]' : el.tagName.toLowerCase())
                        });
                    });
                });
                // Also catch orphan inputs outside <form>
                document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    results.push({
                        tag: el.tagName.toLowerCase(),
                        type: el.type || '',
                        name: el.name || '',
                        id: el.id || '',
                        placeholder: el.placeholder || '',
                        formAction: window.location.href,
                        formMethod: 'GET',
                        visible: rect.width > 0 && rect.height > 0,
                        selector: (el.id ? '#' + el.id : '') ||
                                  (el.name ? '[name="' + el.name + '"]' : el.tagName.toLowerCase())
                    });
                });
                return results;
            }
        """)

        for f in forms:
            vectors.append(InputVector(
                element_type=f.get("type") or f["tag"],
                name=f["name"],
                id=f["id"],
                placeholder=f["placeholder"],
                tag=f["tag"],
                form_action=f["formAction"],
                form_method=f["formMethod"],
                css_selector=f["selector"],
                page_url=page_url,
            ))
        return vectors

    # ------------------------------------------------------------------
    # Active: Script Endpoint Extraction
    # ------------------------------------------------------------------

    async def _extract_script_endpoints(self, page: Page, page_url: str) -> List[ApiEndpoint]:
        endpoints: List[ApiEndpoint] = []
        # Collect all script content (inline + external)
        raw_blocks: List[str] = await page.evaluate("""
            () => {
                const blocks = [];
                document.querySelectorAll('script').forEach(s => {
                    if (s.src) blocks.push('SRC:' + s.src);
                    else blocks.push(s.textContent || '');
                });
                return blocks;
            }
        """)

        for block in raw_blocks:
            source = "script_inline"
            if block.startswith("SRC:"):
                source = "script_static"
                try:
                    resp = await page.request.get(block[4:], timeout=15000)
                    if resp.ok:
                        block = await resp.text()
                    else:
                        continue
                except Exception:
                    continue

            for pattern in self.ENDPOINT_PATTERNS:
                for match in pattern.finditer(block):
                    if pattern is self.ENDPOINT_PATTERNS[3]:  # XHR .open: 2 groups
                        method, path = match.groups()
                        method = method.upper()
                    else:
                        path = match.group(1)
                        method = "GET"  # best-effort default

                    full_url = urljoin(page_url, path)
                    if self._is_in_scope(full_url):
                        endpoints.append(ApiEndpoint(
                            url=full_url,
                            method=method,
                            source=source,
                            origin_page=page_url,
                            content_type="",
                            status_code=0,
                        ))

        return endpoints

    # ------------------------------------------------------------------
    # Internal Link Extraction
    # ------------------------------------------------------------------

    async def _extract_internal_links(self, page: Page, base_domain: str) -> List[str]:
        hrefs: List[str] = await page.evaluate("""
            () => [...document.querySelectorAll('a[href]')].map(a => a.href)
        """)
        links: List[str] = []
        for href in hrefs:
            parsed = urlparse(href)
            if parsed.netloc == base_domain or parsed.netloc == "":
                # Strip fragment for dedup
                clean = parsed._replace(fragment="").geturl()
                if not re.search(r'\.(pdf|zip|png|jpg|jpeg|gif|svg|ico|woff2?|css)$', clean, re.IGNORECASE):
                    links.append(clean)
        return links

    # ------------------------------------------------------------------
    # Network Harvest
    # ------------------------------------------------------------------

    def _harvest_network_endpoints(
        self, network_calls: List[Dict], page_url: str, response_info: Dict
    ) -> List[ApiEndpoint]:
        endpoints: List[ApiEndpoint] = []
        for call in network_calls:
            if not self._is_in_scope(call["url"]):
                continue
            # Filter out static assets
            if re.search(r'\.(png|jpg|jpeg|gif|svg|ico|woff2?|css|js|map)$', call["url"], re.IGNORECASE):
                continue
            endpoints.append(ApiEndpoint(
                url=call["url"],
                method=call["method"],
                source="network",
                origin_page=page_url,
                content_type=response_info.get("content_type", ""),
                status_code=response_info.get("status", 0),
                request_headers=call.get("headers", {}),
            ))
        return endpoints

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise(url: str) -> str:
        p = urlparse(url)
        return p._replace(fragment="", query="").geturl().rstrip("/")

    def _is_in_scope(self, url: str) -> bool:
        try:
            domain = urlparse(url).netloc
        except Exception:
            return False
        return domain in self.allowed_domains

    def _build_report(self, target_url: str, base_domain: str) -> DiscoveryReport:
        # Build hierarchy: link parents -> children
        hierarchy = {url: node for url, node in self._pages.items()}
        return DiscoveryReport(
            target=target_url,
            base_domain=base_domain,
            total_pages=len(self._pages),
            total_input_vectors=len(self._input_vectors),
            total_api_endpoints=len(self._api_endpoints),
            hierarchy=hierarchy,
            input_vector_catalogue=self._input_vectors,
            api_endpoint_catalogue=self._api_endpoints,
            crawl_errors=self._crawl_errors,
        )

    def report_to_json(self, report: DiscoveryReport) -> str:
        return json.dumps(asdict(report), indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python discovery_engine.py <target_url>")
        return
    engine = DiscoveryEngine(headless=True, max_depth=4, max_pages=200, concurrency=6)
    report = await engine.crawl(sys.argv[1])
    print(engine.report_to_json(report))


if __name__ == "__main__":
    asyncio.run(main())