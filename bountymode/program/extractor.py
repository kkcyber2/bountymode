"""Extract a program scope from policy text.

The extractor is deliberately conservative in one direction only: it never
*adds* a target it is unsure about, because a wrongly-included target is an
unauthorized test against a third party.  Anything ambiguous is left out of the
machine-enforced scope and recorded as a ``VERIFY`` marker instead.

Three things make this more than a regex pass over prose:

* **Table rows are the trustworthy source of assets.**  A scope table states
  ``name | tags | known issues`` unambiguously; prose does not.  Hosts are
  therefore harvested from table rows, and from prose only when written as an
  explicit wildcard (``*.example.com``).
* **Third-party listing pages are not targets.**  Many programs list their app
  on a marketplace and put the *listing URL* in the scope table; the testable
  asset is the app's own backend.  A listing host is recorded as a listing and
  automatically excluded, so the tool can never be pointed at the marketplace
  operator's infrastructure.
* **Program prose is policy, not decoration.**  Sentences like “prompt
  injection is out of scope” or “regressions are not rewarded” change what may
  be submitted, so they are turned into prohibitions and notes rather than
  dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import OutOfScopeRule, ProgramScope, ScopeTarget

# --------------------------------------------------------------------------- #
# patterns
# --------------------------------------------------------------------------- #

_URL_RE = re.compile(r"https?://[^\s)|\"'`,;\]]+", re.I)
_WILDCARD_RE = re.compile(r"\*\.(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

#: An in-scope heading.  Real program pages write this many ways: "In Scope",
#: "In-scope targets", "## 2. Scope", "Scope of this program".  A bare "Scope"
#: heading counts, but only when it is not the out-of-scope heading -- the
#: negative lookahead keeps "Out of scope" and "Scope exclusions" out.
_IN_HEAD = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:\d+[.)]\s*)?(?!out\b)(?:in[\s-]?scope|scope)\b"
    r"(?:\s*(?:targets?|assets?|hosts?|domains?|items?))?\b.*$",
    re.I | re.M,
)
_OUT_HEAD = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:\d+[.)]\s*)?out[\s-]?(?:of[\s-]?)?scope"
    r"(?:\s*(?:targets?|assets?|hosts?|domains?|items?))?\b.*$",
    re.I | re.M,
)

#: A line that explicitly presents what follows as a target, e.g.
#: ``**Target row:** `*.openai.com` `` or ``In scope: api.example.com``.
_TARGET_MARKER_RE = re.compile(
    r"\b(?:target(?:s)?\s*(?:row|rows|host|hosts|asset|assets)?|in[\s-]?scope|"
    r"scope\s*(?:targets?|assets?|hosts?))\b\s*[:\-]",
    re.I,
)

#: A backtick-quoted token, which program pages use to set a host apart from
#: surrounding prose.
_BACKTICK_RE = re.compile(r"`([^`\n]{1,200})`")

#: A bullet or numbered list item.
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+\u2022]|\d+[.)])\s+(.*)$")

#: File extensions that are never a testable host, even when backticked.
_NON_HOST_SUFFIXES = (
    ".json", ".md", ".py", ".js", ".ts", ".txt", ".png", ".svg", ".jpg",
    ".yaml", ".yml", ".xml", ".html", ".css", ".pdf", ".csv", ".sh",
)

#: Hosts that are documentation, not a target: the bounty platform itself, the
#: researcher's own test-mailbox domain, and the program's own policy pages.
_NON_TARGET_HOSTS = {
    "bugcrowd.com", "hackerone.com", "intigriti.com", "yeswehack.com",
    "synack.com", "hackenproof.com", "bugcrowdninja.com",
}
_ANY_HEAD = re.compile(r"^\s*#{1,6}\s+.*$", re.M)

_REWARD_LINE = re.compile(r"^\s*P([1-5])\s*\|\s*\$?([\d,]+)\s*$", re.I | re.M)
_REWARD_INLINE = re.compile(
    r"\bP([1-5])\b[^\n$]{0,40}?\$\s?([\d,]+)", re.I
)

_RATE_RE = re.compile(
    r"(\d+)\s*(?:req(?:uest)?s?)\s*(?:per|/)\s*(sec(?:ond)?|min(?:ute)?|hour|h|s)\b", re.I
)
_MAX_REQ_RE = re.compile(
    r"(?:max(?:imum)?|no more than|limit of)\s*(\d{2,7})\s*(?:req|requests)", re.I
)
_DURATION_RE = re.compile(r"(\d+)\s*(hour|hr|h|minute|min)s?\b", re.I)
_DISCLOSURE_RE = re.compile(r"(\d+)[\s-]?day(?:s)?\s*(?:disclosure|embargo|grace)", re.I)

_PLATFORM_HINTS = {
    "bugcrowd": "bugcrowd",
    "hackerone": "hackerone",
    "intigriti": "intigriti",
    "yeswehack": "yeswehack",
    "synack": "synack",
    "hackenproof": "hackenproof",
}

#: Hosts that operate a marketplace/index rather than the program's own
#: application.  Listing the marketplace page is not authorization to test the
#: marketplace, so these are recorded as listings and excluded automatically.
LISTING_HOSTS = {
    "marketplace.atlassian.com",
    "apps.apple.com",
    "play.google.com",
    "chrome.google.com",
    "chromewebstore.google.com",
    "addons.mozilla.org",
    "marketplace.visualstudio.com",
    "apps.microsoft.com",
    "github.com",
    "gitlab.com",
    "npmjs.com",
    "pypi.org",
    "hub.docker.com",
    "aws.amazon.com",
    "azuremarketplace.microsoft.com",
    "console.cloud.google.com",
}

#: Policy prose -> the technique it forbids.
_PROHIBITED_PATTERNS: List[Tuple[str, str]] = [
    (r"prompt injection", "prompt_injection"),
    (r"denial of wallet|cost,? volume or load|resource exhaustion|unbounded consumption", "economic_denial"),
    (r"denial[- ]of[- ]service|\bdos\b|\bddos\b", "economic_denial"),
    (r"rate limit", "economic_denial"),
    (r"unattended mass scanning|mass scanning|automated mass", "automated_scanner"),
    (r"social engineer", "social_bot_auditor"),
    (r"\bphishing\b", "social_bot_auditor"),
    (r"malware", "malware"),
    (r"\bphysical(?: security)?\b", "physical"),
    (r"self[- ]?xss", "self_xss"),
    (r"clickjacking", "clickjacking"),
    (r"\bgenerated (?:text|content)|model (?:behavior|behaviour)", "model_behavior"),
]

#: Policy prose worth surfacing verbatim in the notes.
_NOTE_PATTERNS: List[str] = [
    r"one root cause earns one bounty[^.]*\.",
    r"\d+[-\s]?day bounty grace period[^.]*\.",
    r"regressions are not rewarded[^.]*\.",
    r"unattended mass scanning[^.]*\.",
    r"a human verifies every finding[^.]*\.",
    r"human directs them[^.]*\.",
    r"duplicate[^.]*\.",
    r"chain[^.]*\.",
    r"test account[^.]*\.",
]


# --------------------------------------------------------------------------- #
# results
# --------------------------------------------------------------------------- #

@dataclass
class ExtractedProgram:
    """A parsed program plus the audit trail of how it was parsed."""

    scope: ProgramScope
    listings: List[Dict[str, str]] = field(default_factory=list)
    rewards: Dict[str, int] = field(default_factory=dict)
    report: "ExtractionReport" = None  # type: ignore[assignment]

    def to_dict(self) -> dict:
        return {
            "scope": self.scope.to_dict(),
            "listings": list(self.listings),
            "rewards": dict(self.rewards),
            "report": self.report.to_dict() if self.report else {},
        }


@dataclass
class ExtractionReport:
    """What the extractor did, and everything it was unsure about."""

    source: str = "text"
    url: str = ""
    title: str = ""
    confidence: float = 0.0
    verify: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "url": self.url,
            "title": self.title,
            "confidence": round(self.confidence, 3),
            "verify": list(self.verify),
            "notes": list(self.notes),
            "warnings": list(self.warnings),
            "stats": dict(self.stats),
        }

    @property
    def grade(self) -> str:
        if self.confidence >= 0.75:
            return "high"
        if self.confidence >= 0.45:
            return "medium"
        return "low"


# --------------------------------------------------------------------------- #
# extractor
# --------------------------------------------------------------------------- #

class ProgramExtractor:
    """Turn policy text into a conservative, reviewable program scope."""

    def extract(
        self,
        text: str,
        *,
        program: Optional[str] = None,
        platform: Optional[str] = None,
        url: str = "",
        title: str = "",
        source: str = "text",
    ) -> ExtractedProgram:
        text = text or ""
        report = ExtractionReport(source=source, url=url, title=title)

        name = (program or self._program_name(text, title, url) or "imported-program").strip()
        plat = (platform or self._platform(text, url)).strip().lower() or "generic"

        in_block = _slice_section(text, _IN_HEAD, _OUT_HEAD)
        out_block = _slice_section(text, _OUT_HEAD, _IN_HEAD)

        in_rows = _table_rows(in_block)
        kind_col = _kind_column(in_rows)
        listings: List[Dict[str, str]] = []
        in_scope: List[ScopeTarget] = []
        seen: set = set()

        for row in in_rows:
            declared = row[kind_col] if 0 <= kind_col < len(row) else ""
            for target in _targets_from_row(row):
                key = target.lower()
                if key in seen:
                    continue
                seen.add(key)
                host = _host_of(target)
                if host and _is_listing(host):
                    listings.append({"url": target, "host": host,
                                     "note": "marketplace/listing page \u2014 the testable "
                                             "asset is the app backend, not this host"})
                    continue
                in_scope.append(ScopeTarget(pattern=target, kind=_kind_of(target, declared)))

        # Explicit statements only -- never bare hosts from ordinary prose.
        # A program page states its assets in one of three explicit ways: a
        # wildcard, a backtick-quoted host, or a line that names the host as a
        # target ("Target row: `*.openai.com`").  Anything else is left out,
        # because a wrongly-included target is an unauthorized test.
        if not in_scope:
            for target in _explicit_targets(in_block):
                key = target.lower()
                if key not in seen:
                    seen.add(key)
                    in_scope.append(ScopeTarget(pattern=key, kind=_kind_of(key)))

        # No in-scope heading at all (a pasted brief often has none): fall back
        # to explicit target statements anywhere outside the out-of-scope
        # section, plus any scope table.  Exclusions still win, so this cannot
        # authorize an excluded host.
        if not in_scope:
            haystack = _remove_sections(text, _OUT_HEAD, _IN_HEAD)
            for target in _explicit_targets(haystack):
                key = target.lower()
                if key not in seen:
                    seen.add(key)
                    in_scope.append(ScopeTarget(pattern=key, kind=_kind_of(key)))
        if not in_scope:
            for row in _table_rows(text):
                for target in _targets_from_row(row):
                    key = target.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    in_scope.append(ScopeTarget(pattern=key, kind=_kind_of(key)))

        out_of_scope = _out_of_scope_rules(out_block)

        # A listing host is automatically excluded: the program never
        # authorized testing the marketplace operator.  The same host usually
        # appears once per listed app, so the rules are de-duplicated.
        for lst in listings:
            out_of_scope.append(
                OutOfScopeRule(
                    pattern=lst["host"],
                    reason="third-party marketplace/listing host \u2014 the testable "
                           "asset is the app backend it points to, not this host",
                    kind="host",
                )
            )
        out_of_scope = _dedup_rules(out_of_scope)

        rewards = self._rewards(text)
        prohibited = self._prohibited(text)
        rate_rps, max_req = self._limits(text)
        notes = self._notes(text)
        requires_human = bool(
            re.search(r"(?:a )?human (?:verifies|reviews|directs)", text, re.I)
            or re.search(r"manual verification required", text, re.I)
        )

        scope = ProgramScope(
            program=name,
            platform=plat,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            prohibited_techniques=prohibited,
            rate_limit_rps=rate_rps,
            max_requests=max_req,
            max_duration_s=self._duration(text),
            requires_test_account=bool(re.search(r"test account|research account", text, re.I)),
            safe_harbour=_safe_harbour(text),
            disclosure_days=self._disclosure(text),
            source_url=url,
            raw_hash=_sha16(text),
            reward_table=dict(rewards),
            listings=list(listings),
            notes=notes,
            requires_human_verification=requires_human,
            program_url=url,
        )

        self._annotate(report, scope, listings, rewards, text)
        return ExtractedProgram(scope=scope, listings=listings, rewards=rewards, report=report)

    # -- helpers ----------------------------------------------------------- #

    def _program_name(self, text: str, title: str, url: str) -> str:
        if title:
            cleaned = re.sub(r"\s*[-|]\s*Bugcrowd\s*$", "", title, flags=re.I)
            cleaned = re.sub(r"^Bug Bounty:\s*", "", cleaned, flags=re.I)
            cleaned = re.sub(r"\s*Bug Bounty Program\s*$", "", cleaned, flags=re.I)
            cleaned = cleaned.strip(" -|")
            if cleaned:
                return cleaned
        m = re.search(r"^\s*#+\s*(.+?)\s*$", text, re.M)
        if m:
            return m.group(1).strip()
        if url:
            tail = url.rstrip("/").split("/")[-1]
            if tail and tail not in ("engagements", "programs"):
                return tail
        return "imported-program"

    def _platform(self, text: str, url: str) -> str:
        hay = f"{url} {text[:4000]}".lower()
        for needle, name in _PLATFORM_HINTS.items():
            if needle in hay:
                return name
        return "generic"

    def _rewards(self, text: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for key, amount in _REWARD_LINE.findall(text):
            out[f"P{key}"] = int(amount.replace(",", ""))
        if not out:
            for key, amount in _REWARD_INLINE.findall(text):
                out.setdefault(f"P{key}", int(amount.replace(",", "")))
        if not out:
            out = _severity_rewards(text)
        return dict(sorted(out.items()))

    def _prohibited(self, text: str) -> List[str]:
        found = {"economic_denial", "destructive", "malware"}
        for pattern, tid in _PROHIBITED_PATTERNS:
            if re.search(pattern, text, re.I):
                found.add(tid)
        return sorted(found)

    def _limits(self, text: str) -> Tuple[float, int]:
        rps, max_req = 1.0, 500
        m = _RATE_RE.search(text)
        if m:
            n, unit = max(1, int(m.group(1))), m.group(2).lower()
            rps = float(n) if unit.startswith("s") else (n / 60.0 if unit.startswith("min") else n / 3600.0)
            rps = max(rps, 0.01)
        m2 = _MAX_REQ_RE.search(text)
        if m2:
            max_req = max(1, int(m2.group(1)))
        return rps, max_req

    def _duration(self, text: str) -> int:
        m = _DURATION_RE.search(text)
        if not m:
            return 1800
        n = int(m.group(1))
        return n * 3600 if m.group(2).lower().startswith("h") else n * 60

    def _disclosure(self, text: str) -> int:
        m = _DISCLOSURE_RE.search(text)
        return int(m.group(1)) if m else 90

    def _notes(self, text: str) -> List[str]:
        out: List[str] = []
        for pattern in _NOTE_PATTERNS:
            for m in re.finditer(pattern, text, re.I):
                sentence = " ".join(m.group(0).split())
                if sentence and sentence not in out and len(sentence) > 12:
                    out.append(sentence)
        return out[:12]

    def _annotate(
        self,
        report: ExtractionReport,
        scope: ProgramScope,
        listings: List[Dict[str, str]],
        rewards: Dict[str, int],
        text: str,
    ) -> None:
        verify = report.verify

        if not scope.in_scope:
            verify.append(
                "No directly testable in-scope asset was found. If the program lists "
                "its app on a marketplace, add the app's own backend host(s) manually "
                "and confirm them against the program's scope page."
            )
        for target in scope.in_scope:
            verify.append(
                f"Asset '{target.pattern}' was parsed from the scope table — confirm "
                "it is listed and that you may test it."
            )
        if listings:
            verify.append(
                f"{len(listings)} in-scope entr{'y' if len(listings) == 1 else 'ies'} are "
                "marketplace/listing pages, not testable hosts; they were excluded "
                "automatically. Add the app's own host(s) if the program allows it."
            )
            if not scope.in_scope:
                verify.append(
                    "Every in-scope entry on this page is a marketplace listing. The "
                    "program's own scope text usually says the testable asset is the "
                    "backend the app calls \u2014 find that host, add it here, and confirm "
                    "it before running anything."
                )
        if scope.out_of_scope:
            verify.append(
                "Out-of-scope rules were extracted from prose/tables. Review them — "
                "an exclusion the parser missed is the most dangerous kind of error."
            )
        if not rewards:
            verify.append(
                "No reward table was found. Confirm the payout ranges on the program "
                "page before prioritising work."
            )
        if scope.requires_human_verification:
            verify.append(
                "The program requires a human to verify every finding; unverified "
                "automated output is not eligible for a bounty here."
            )
        if re.search(r"\bduplicate", text, re.I):
            verify.append(
                "The program's duplicate policy is significant — check it before "
                "spending effort on a known issue class."
            )

        earned = 0.0
        earned += 0.30 if scope.in_scope else 0.0
        earned += 0.15 if rewards else 0.0
        earned += 0.15 if scope.out_of_scope else 0.0
        earned += 0.15 if len(scope.prohibited_techniques) > 3 else 0.0
        earned += 0.15 if scope.program and scope.program != "imported-program" else 0.0
        earned += 0.10 if scope.source_url else 0.0
        report.confidence = min(1.0, earned)

        report.stats = {
            "in_scope": len(scope.in_scope),
            "out_of_scope": len(scope.out_of_scope),
            "listings": len(listings),
            "prohibited": len(scope.prohibited_techniques),
            "rewards": len(rewards),
            "notes": len(scope.notes),
            "verify": len(verify),
        }

        scope.verify_markers = list(verify)


# --------------------------------------------------------------------------- #
# module helpers
# --------------------------------------------------------------------------- #

def _section_spans(text: str, head: re.Pattern, other: re.Pattern) -> List[Tuple[int, int]]:
    """Return the ``(start, end)`` span of every section whose heading matches.

    A real program page often states its scope in more than one place -- a
    summary table near the top and a full list further down.  Taking only the
    first match silently drops the rest, so all matches are collected.  Each
    section runs to the next heading of any kind (or to the competing heading),
    which keeps a section from swallowing the whole document.
    """
    spans: List[Tuple[int, int]] = []
    for m in head.finditer(text):
        rest = text[m.end():]
        nxt = other.search(rest)
        nxt_any = _ANY_HEAD.search(rest)
        stops = [s.start() for s in (nxt, nxt_any) if s]
        end = m.end() + (min(stops) if stops else len(rest))
        spans.append((m.start(), end))
    return spans


def _slice_section(text: str, head: re.Pattern, other: re.Pattern) -> str:
    """Concatenate the text of every section whose heading matches ``head``."""
    return "\n".join(text[s:e] for s, e in _section_spans(text, head, other))


def _remove_sections(text: str, head: re.Pattern, other: re.Pattern) -> str:
    """Blank out every section whose heading matches ``head``.

    Used to build a haystack that cannot see the out-of-scope section, so a
    host mentioned only as an exclusion can never be harvested as a target.
    Blanking by span (rather than a string replace) matters because the matched
    sections are not contiguous in the original text.
    """
    chars = list(text)
    for start, end in _section_spans(text, head, other):
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def _table_rows(block: str) -> List[List[str]]:
    rows: List[List[str]] = []
    for line in (block or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells:
            rows.append(cells)
    return rows


def _targets_from_row(row: List[str]) -> List[str]:
    """Pull candidate assets out of a scope-table row's first cell."""
    if not row:
        return []
    blob = row[0]
    out: List[str] = []
    for url in _URL_RE.findall(blob):
        cleaned = url.rstrip(".,;)")
        if cleaned and cleaned.lower() not in out:
            out.append(cleaned)
    if not out:
        for wildcard in _WILDCARD_RE.findall(blob):
            if wildcard.lower() not in out:
                out.append(wildcard.lower())
    if not out:
        for host in _HOST_RE.findall(blob):
            h = host.lower().strip(".")
            if not _is_testable_host(h):
                continue
            if h not in out:
                out.append(h)
    return out


def _explicit_targets(block: str) -> List[str]:
    """Harvest assets a program states *explicitly*, never from bare prose.

    Three explicit forms are recognised, in order of trust:

    1. a wildcard (``*.example.com``) -- unambiguous;
    2. a backtick-quoted host (`` `api.example.com` ``) -- the page set it apart
       from the sentence on purpose;
    3. a host on a line that names it as a target (``Target row: api.example.com``).

    A host that merely appears inside a sentence is *not* harvested: including a
    target the program never listed would be an unauthorized test.
    """
    out: List[str] = []
    seen: set = set()

    def add(value: str) -> None:
        value = (value or "").strip().strip(".,;:()[]<>\"'")
        if not value:
            return
        if not _is_testable_host(value):
            return
        key = value.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(value)

    for line in (block or "").splitlines():
        for wildcard in _WILDCARD_RE.findall(line):
            add(wildcard.lower())

        for token in _BACKTICK_RE.findall(line):
            for host in _HOST_RE.findall(token):
                add(host.lower())

        if _TARGET_MARKER_RE.search(line):
            for host in _HOST_RE.findall(line):
                add(host.lower())

        # A line that is *only* a host -- with or without a bullet, and with
        # optional markdown emphasis -- is a target statement.  This is how a
        # pasted scope list ("- api.example.com") and a heading followed by a
        # bare host list both read.
        item = _LIST_ITEM_RE.match(line)
        content = item.group(1) if item else line
        content = content.strip().strip("*_` ").strip()
        if content and _HOST_RE.fullmatch(content):
            add(content.lower())

    return out


def _is_testable_host(value: str) -> bool:
    """Is this token plausibly a host a program would authorize testing?

    Rejects file names (``ai-plugin.json``), the bounty platform's own hosts,
    and the researcher's test-mailbox domain -- none of which are targets, and
    all of which a naive host regex happily picks up out of prose.
    """
    host = _host_of(value)
    if not host or "." not in host:
        return False
    if host.endswith(_NON_HOST_SUFFIXES):
        return False
    if host in _NON_TARGET_HOSTS:
        return False
    if any(host.endswith("." + h) for h in _NON_TARGET_HOSTS):
        return False
    return True


def _host_of(target: str) -> str:
    t = (target or "").strip().lower()
    if t.startswith("*."):
        t = t[2:]
    t = re.sub(r"^https?://", "", t)
    return t.split("/")[0].split(":")[0].strip(".")


def _base_domain(host: str) -> str:
    """Return the registrable-ish base for a host (last two labels)."""
    parts = [p for p in (host or "").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _is_listing(host: str) -> bool:
    host = (host or "").lower()
    if not host:
        return False
    if host in LISTING_HOSTS:
        return True
    return any(host == lh or host.endswith("." + lh) for lh in LISTING_HOSTS)


def _kind_of(target: str, declared: str = "") -> str:
    """Classify an asset, preferring the program's own declared kind.

    A scope table usually has a column saying what the row *is* ("api", "web",
    "mobile", "llm").  That is the program's own statement and outranks any
    guess from the hostname, so it is honoured first.
    """
    declared = (declared or "").strip().lower()
    if declared:
        for kind in ("llm", "api", "mobile", "web", "cloud", "repo"):
            if kind in declared:
                return kind
        if "android" in declared or "ios" in declared or "app" in declared:
            return "mobile"
    t = (target or "").lower()
    if t.endswith(".apk") or "android" in t:
        return "mobile"
    if t.endswith(".ipa") or "ios" in t:
        return "mobile"
    if "/api" in t or t.startswith("api.") or "graphql" in t:
        return "api"
    if any(s in t for s in ("llm", "chat", "assistant", "copilot", "ai.")):
        return "llm"
    return "web"


#: A scope-table header cell that names the asset-kind column.
_KIND_HEADER_RE = re.compile(r"\b(kind|type|asset\s*type|category|platform)\b", re.I)


def _kind_column(rows: List[List[str]]) -> int:
    """Find the index of the asset-kind column in a scope table, if any."""
    for row in rows[:2]:
        for index, cell in enumerate(row):
            if _KIND_HEADER_RE.search(cell or ""):
                return index
    return -1


#: A reward table keyed by severity name rather than by P1..P5.  The amount may
#: be written with or without a currency symbol, and may sit in a table cell.
_SEVERITY_REWARD_RE = re.compile(
    r"\b(critical|high|medium|low|informational)\b[^\n\d$]{0,40}?\$?\s?([\d][\d,]{1,})\b",
    re.I,
)

#: Severity name -> the P-level the rest of the system uses.
_SEVERITY_TO_P = {
    "critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "informational": "P5",
}


def _severity_rewards(text: str) -> Dict[str, int]:
    """Parse a reward table keyed by severity name (Critical/High/...)."""
    out: Dict[str, int] = {}
    for name, amount in _SEVERITY_REWARD_RE.findall(text or ""):
        level = _SEVERITY_TO_P.get(name.lower())
        if level and level not in out:
            out[level] = int(amount.replace(",", ""))
    return out


def _dedup_rules(rules: List[OutOfScopeRule]) -> List[OutOfScopeRule]:
    """Collapse rules that say the same thing about the same pattern.

    A real program page repeats one exclusion per listed app, so without this
    the report shows dozens of identical lines and the signal is lost.
    """
    seen: set = set()
    out: List[OutOfScopeRule] = []
    for rule in rules:
        key = (rule.pattern.lower(), rule.kind)
        if key in seen:
            continue
        seen.add(key)
        out.append(rule)
    return out


def _out_of_scope_rules(block: str) -> List[OutOfScopeRule]:
    """Build exclusion rules from the out-of-scope section.

    Only host-shaped items become hard exclusions; prose items become
    ``kind='technique'`` rules (recorded, never used to *authorize*) plus a
    human-readable reason, which keeps the section useful without pretending a
    paragraph is a host pattern.
    """
    rules: List[OutOfScopeRule] = []
    seen: set = set()

    for row in _table_rows(block):
        for host in _HOST_RE.findall(row[0] if row else ""):
            h = host.lower().strip(".")
            if h in seen:
                continue
            seen.add(h)
            reason = " | ".join(c for c in row[1:] if c)[:120]
            rules.append(OutOfScopeRule(pattern=h, reason=reason or "listed as out of scope"))

    for line in (block or "").splitlines():
        line = line.strip()
        if not line or line.startswith("|"):
            continue
        for wildcard in _WILDCARD_RE.findall(line):
            w = wildcard.lower()
            if w not in seen:
                seen.add(w)
                rules.append(OutOfScopeRule(pattern=w, reason="listed as out of scope"))
        # A bare host (or comma-separated list of hosts) inside the out-of-scope
        # section is an exclusion.  Unlike in-scope hosts, capturing these is the
        # safe direction: an exclusion can only ever deny more.
        for host in _HOST_RE.findall(line):
            h = host.lower().strip(".")
            if h in seen or _is_listing(h):
                continue
            seen.add(h)
            rules.append(OutOfScopeRule(pattern=h, reason="listed as out of scope"))
        if re.search(r"\bout of scope\b|\bnot (?:eligible|rewarded|in scope)\b|\bexcluded\b", line, re.I):
            cleaned = " ".join(line.split())
            # Skip the section's own lead-in ("The following are out of scope:")
            # and the heading itself -- they are not rules, and recording them
            # as patterns produces junk exclusions.
            is_lead_in = cleaned.rstrip(":").lower() in {
                "the following are out of scope",
                "the following is out of scope",
                "out of scope",
                "out-of-scope",
                "not eligible",
                "excluded",
            } or (cleaned.endswith(":") and not _HOST_RE.search(cleaned))
            if len(cleaned) > 20 and cleaned not in seen and not is_lead_in:
                seen.add(cleaned)
                rules.append(OutOfScopeRule(pattern=cleaned, reason="program prose", kind="technique"))

    return rules


def _safe_harbour(text: str) -> bool:
    return bool(re.search(r"safe[\s-]?harbou?r", text, re.I))


def _sha16(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
