"""Fetch a public bug-bounty program page into text.

A program page is the only input a new user starts with, so the onboarding
layer's first job is to turn that page into text an extractor can read —
without a third-party dependency, and without ever pretending a failed fetch
succeeded.

Strategy, in order
------------------

1. **Static HTML** (standard library only).  Fast, no browser, and sufficient
   for platforms that server-render scope (most HackerOne programs).
2. **Headless browser**, used only when ``agent-browser`` is on ``PATH``.
   Bugcrowd renders its scope table client-side, so the static document
   contains no in-scope assets at all.  The browser is asked for its
   accessibility tree rather than the DOM, because the tree is stable text
   while CSS selectors are not.
3. **Paste mode**.  When neither works, the caller is told exactly what to copy
   and from where, and can hand the text straight to
   :meth:`ProgramFetcher.from_text`.

The module never decides what is in scope — that is the extractor's job — and
it never raises on a failure it can describe instead.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional

#: A real browser UA.  Several platforms serve a stub to obvious bots.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
)

#: Substrings that indicate a program page actually described its scope.
_SCOPE_HEADINGS = (
    "in scope",
    "in-scope",
    "scope of work",
    "out of scope",
    "out-of-scope",
    "exclusions",
    "eligible assets",
    "targets",
)

_URL_RE = re.compile(r"https?://[^\s)|\"'`,;\]]+", re.I)
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _scope_signal(text: str) -> bool:
    """Does this text look like it actually contains a program scope?

    A shell page still contains the words “scope” and “reward” in its chrome,
    so the test requires a scope *heading* and at least one concrete asset.
    """
    low = text.lower()
    if not any(h in low for h in _SCOPE_HEADINGS):
        return False
    return bool(_URL_RE.search(text) or _HOST_RE.search(text))


def _readable_length(text: str) -> int:
    return len(re.sub(r"\s+", " ", text).strip())


# --------------------------------------------------------------------------- #
# HTML -> text
# --------------------------------------------------------------------------- #

class _HtmlTextExtractor(HTMLParser):
    """Extract readable text, preserving table rows as pipe-delimited lines.

    Rows matter: a scope table is the one place a program states its assets
    unambiguously, and flattening it to prose loses that structure.
    """

    SKIP = {"script", "style", "noscript", "svg", "template", "iframe"}
    BLOCK = {"p", "div", "li", "table", "section", "article", "header", "footer", "ul", "ol"}
    HEADING = {"h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False
        self._cell: Optional[List[str]] = None
        self._row: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag in ("td", "th"):
            self._cell = []
        elif tag == "tr":
            self._row = []
        elif tag == "br":
            self.parts.append("\n")
        elif tag in self.HEADING:
            self.parts.append("\n## ")
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False
        elif tag in ("td", "th"):
            text = " ".join("".join(self._cell or []).split())
            if text:
                self._row.append(text)
            self._cell = None
        elif tag == "tr":
            if self._row:
                self.parts.append("\n| " + " | ".join(self._row) + " |")
            self._row = []
        elif tag in self.HEADING or tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._in_title:
            self.title += data
            return
        if self._cell is not None:
            self._cell.append(data)
            return
        self.parts.append(data)

    def text(self) -> str:
        return _tidy("".join(self.parts))


def html_to_text(html: str) -> str:
    """Extract readable text from an HTML document."""
    parser = _HtmlTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - a malformed page must not be fatal
        pass
    return parser.text()


def html_title(html: str) -> str:
    parser = _HtmlTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001
        pass
    return " ".join(parser.title.split())


def _tidy(text: str) -> str:
    """Normalise whitespace while keeping paragraph breaks and table rows."""
    lines = [" ".join(line.split()) if line.strip() else "" for line in text.splitlines()]
    out: List[str] = []
    for line in lines:
        if not line and out and not out[-1]:
            continue
        out.append(line)
    return "\n".join(out).strip()


# --------------------------------------------------------------------------- #
# accessibility tree -> text
# --------------------------------------------------------------------------- #

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _first_quoted(body: str) -> str:
    m = _QUOTED.search(body)
    if not m:
        return ""
    return m.group(1).replace('\\"', '"').replace("\\\\", "\\")


def snapshot_to_text(snapshot: str) -> str:
    """Render an ``agent-browser snapshot`` accessibility tree as readable text.

    Headings become ``##`` lines, table rows become pipe-delimited lines and
    description-list term/value pairs become ``TERM | VALUE`` lines, so the
    scope table and the reward chart survive the conversion.
    """
    out: List[str] = []
    row: List[str] = []
    row_indent: Optional[int] = None
    pending_term: Optional[str] = None
    awaiting_value = False

    def flush_row() -> None:
        nonlocal row, row_indent
        if row:
            out.append("| " + " | ".join(row) + " |")
        row = []
        row_indent = None

    for raw in snapshot.splitlines():
        stripped = raw.rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        body = stripped.strip()
        if not body.startswith("- "):
            continue
        body = body[2:]
        kind = body.split(" ", 1)[0] if body else ""
        text = _first_quoted(body)

        if row and row_indent is not None and indent <= row_indent and kind not in (
            "cell", "columnheader", "row",
        ):
            flush_row()

        if kind == "row":
            flush_row()
            row_indent = indent
        elif kind in ("cell", "columnheader"):
            if row_indent is None:
                row_indent = max(0, indent - 2)
            if text:
                row.append(text)
        elif kind == "term":
            pending_term = text or None
        elif kind == "definition":
            awaiting_value = True
        elif kind == "StaticText":
            if row:
                continue  # already captured from the owning cell
            if awaiting_value and pending_term:
                out.append(f"{pending_term} | {text}")
                pending_term, awaiting_value = None, False
            elif text:
                out.append(text)
        elif kind == "heading":
            if text:
                out.append("")
                out.append("## " + text)
                out.append("")
        elif kind in ("link", "text"):
            if row:
                continue
            if text:
                out.append(text)

    flush_row()
    return _tidy("\n".join(out))


# --------------------------------------------------------------------------- #
# result
# --------------------------------------------------------------------------- #

@dataclass
class FetchResult:
    """Outcome of turning a program URL (or pasted text) into policy text."""

    ok: bool
    url: str = ""
    source: str = "none"          # static | browser | paste | none
    text: str = ""
    title: str = ""
    status: int = 0
    warnings: List[str] = field(default_factory=list)
    error: str = ""
    paste_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "url": self.url,
            "source": self.source,
            "title": self.title,
            "status": self.status,
            "chars": len(self.text),
            "warnings": list(self.warnings),
            "error": self.error,
            "paste_hint": self.paste_hint,
        }


def _looks_like_a_program_page(text: str, title: str) -> bool:
    """Does this look like a program page whose scope is rendered lazily?

    A program page that rendered its shell but not its scope table is a
    different situation from a page that failed to load, and the operator needs
    to be told which one they are in.
    """
    hay = f"{title}\n{text[:4000]}".lower()
    return "bug bounty" in hay and ("scope" in hay or "targets" in hay)


def _paste_hint(url: str) -> str:
    return (
        "Could not read the program scope automatically.\n"
        f"  1. Open {url or 'the program page'} in a browser.\n"
        "  2. Select the scope section (In-scope targets, out-of-scope items "
        "and the rules), copy it.\n"
        "  3. Paste it into the import box (UI) or save it to a file and run:\n"
        "       bountymode program import --file scope.txt --program <name>\n"
        "  The parser accepts plain text, the page HTML, or an accessibility "
        "snapshot \u2014 paste whichever you have."
    )


# --------------------------------------------------------------------------- #
# fetcher
# --------------------------------------------------------------------------- #

class ProgramFetcher:
    """Fetch a program page as text, falling back safely."""

    def __init__(
        self,
        *,
        browser: bool = True,
        timeout: float = 30.0,
        browser_timeout: float = 150.0,
        browser_wait_ms: int = 6000,
    ) -> None:
        self.browser = browser
        self.timeout = timeout
        self.browser_timeout = browser_timeout
        #: How long to let a client-rendered page settle before snapshotting.
        #: Program platforms render their scope table after the shell loads, so
        #: snapshotting immediately captures navigation chrome and nothing else.
        self.browser_wait_ms = max(0, int(browser_wait_ms))

    # -- public ------------------------------------------------------------ #

    def fetch(self, url: str) -> FetchResult:
        url = (url or "").strip()
        if not url:
            return FetchResult(ok=False, error="no URL given", paste_hint=_paste_hint(""))
        if "://" not in url:
            url = "https://" + url

        result = self._fetch_static(url)
        if result.ok and _scope_signal(result.text):
            return result

        browser_title = ""
        # The static document is a shell (client-rendered scope), or the fetch
        # failed outright.  Try a real browser before giving up.
        if self.browser and self._browser_available():
            browser_result = self._fetch_browser(url)
            browser_title = browser_result.title
            if browser_result.ok and _scope_signal(browser_result.text):
                if result.warnings:
                    browser_result.warnings = list(result.warnings) + list(browser_result.warnings)
                return browser_result
            if result.ok:
                result.warnings.append(
                    "the page was fetched but its scope section could not be read "
                    "(client-rendered or behind a login)"
                )
            if not result.ok:
                result.error = browser_result.error or result.error
            if browser_result.title and not result.title:
                result.title = browser_result.title

        if result.ok and not _scope_signal(result.text):
            if _looks_like_a_program_page(result.text, result.title or browser_title):
                result.warnings.append(
                    "the program page loaded but its scope section is rendered in a "
                    "tab that does not appear in the accessibility tree \u2014 use paste mode"
                )
            else:
                result.warnings.append(
                    "no scope section found in the fetched document \u2014 the page is "
                    "probably rendered by JavaScript; use paste mode"
                )

        result.paste_hint = _paste_hint(url)
        return result

    def from_text(self, text: str, *, url: str = "") -> FetchResult:
        """Accept pasted policy text, page HTML or an accessibility snapshot."""
        raw = text or ""
        if not raw.strip():
            return FetchResult(ok=False, url=url, error="no text supplied",
                               paste_hint=_paste_hint(url))
        source, normalised, title = normalise_pasted(raw)
        return FetchResult(
            ok=True,
            url=url,
            source="paste",
            text=normalised,
            title=title,
            warnings=[f"input interpreted as {source}"],
        )

    # -- static ------------------------------------------------------------ #

    def _fetch_static(self, url: str) -> FetchResult:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                status = getattr(resp, "status", 0) or 0
                body = resp.read()
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            return FetchResult(
                ok=False, url=url, source="static", status=exc.code,
                error=f"HTTP {exc.code} while fetching the program page",
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return FetchResult(ok=False, url=url, source="static",
                               error=f"could not reach the program page: {exc}")

        html = body.decode("utf-8", errors="replace")
        if "json" in ctype.lower() and not html.lstrip().startswith("<"):
            return FetchResult(ok=True, url=url, source="static", status=status,
                               text=_tidy(html), title="")
        return FetchResult(
            ok=True, url=url, source="static", status=status,
            text=html_to_text(html), title=html_title(html),
        )

    # -- browser ----------------------------------------------------------- #

    @staticmethod
    def _browser_available() -> bool:
        return shutil.which("agent-browser") is not None

    def _fetch_browser(self, url: str) -> FetchResult:
        bin_path = shutil.which("agent-browser")
        if not bin_path:  # pragma: no cover - guarded by _browser_available
            return FetchResult(ok=False, url=url, source="browser",
                               error="agent-browser is not installed")
        try:
            opened = subprocess.run(  # noqa: S603
                [bin_path, "open", url],
                capture_output=True, text=True, timeout=self.browser_timeout,
                check=False,
            )
            title = ""
            for line in (opened.stdout or "").splitlines():
                if line.strip().startswith("\u2713"):
                    title = line.strip().lstrip("\u2713 ").strip()
                    break
            if self.browser_wait_ms:
                subprocess.run(  # noqa: S603
                    [bin_path, "wait", str(self.browser_wait_ms)],
                    capture_output=True, text=True,
                    timeout=self.browser_timeout, check=False,
                )
            snap = subprocess.run(  # noqa: S603
                [bin_path, "snapshot"],
                capture_output=True, text=True, timeout=self.browser_timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return FetchResult(ok=False, url=url, source="browser",
                               error=f"headless browser failed: {exc}")
        finally:
            try:
                subprocess.run([bin_path, "close"], capture_output=True,  # noqa: S603
                               text=True, timeout=30, check=False)
            except (subprocess.TimeoutExpired, OSError):
                pass

        snapshot = snap.stdout or ""
        if not snapshot.strip():
            # A leftover browser session from an earlier run can leave the CLI
            # attached to a dead target, which returns an empty tree.  Clearing
            # sessions and retrying once turns that transient failure into a
            # success instead of a spurious "page not readable".
            try:
                subprocess.run([bin_path, "close", "--all"], capture_output=True,  # noqa: S603
                               text=True, timeout=60, check=False)
                subprocess.run([bin_path, "open", url], capture_output=True,  # noqa: S603
                               text=True, timeout=self.browser_timeout, check=False)
                if self.browser_wait_ms:
                    subprocess.run(  # noqa: S603
                        [bin_path, "wait", str(self.browser_wait_ms)],
                        capture_output=True, text=True,
                        timeout=self.browser_timeout, check=False,
                    )
                snap = subprocess.run(  # noqa: S603
                    [bin_path, "snapshot"], capture_output=True, text=True,
                    timeout=self.browser_timeout, check=False,
                )
                snapshot = snap.stdout or ""
            except (subprocess.TimeoutExpired, OSError):
                pass

        if not snapshot.strip():
            return FetchResult(
                ok=False, url=url, source="browser",
                error=(snap.stderr or "headless browser returned an empty snapshot").strip()[:300],
            )
        return FetchResult(
            ok=True, url=url, source="browser", status=0,
            text=snapshot_to_text(snapshot), title=title,
        )

# --------------------------------------------------------------------------- #
# paste normalisation
# --------------------------------------------------------------------------- #

_SNAPSHOT_HINT = re.compile(r"\[ref=e\d+\]")
_HTML_HINT = re.compile(r"<\s*(?:html|body|div|table|head|section)\b", re.I)


def normalise_pasted(raw: str):
    """Detect the pasted shape and normalise it to readable policy text.

    Returns ``(shape, text, title)`` where shape is ``snapshot`` / ``html`` /
    ``text``.
    """
    if len(_SNAPSHOT_HINT.findall(raw)) >= 3:
        return "snapshot", snapshot_to_text(raw), ""
    if _HTML_HINT.search(raw):
        return "html", html_to_text(raw), html_title(raw)
    return "text", _tidy(raw), ""
