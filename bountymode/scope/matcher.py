"""Target/scope matching.

The only job of this module is to answer one question safely and
deterministically: **does this program's policy cover this target?**

Matching is intentionally conservative.  When a rule is ambiguous we treat the
target as *not* covered, because a false negative costs one skipped test while
a false positive is an unauthorized test against a third party.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from ..models import OutOfScopeRule, ProgramScope, ScopeTarget

_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")


def normalize_target(target: str) -> Tuple[str, str]:
    """Return ``(host, url)`` normalised from a bare host or full URL.

    >>> normalize_target("HTTPS://API.Example.com:443/v1/chat")
    ('api.example.com', 'https://api.example.com:443/v1/chat')
    """
    raw = (target or "").strip()
    if not raw:
        return "", ""
    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else f"https://{raw}")
    host = (parsed.hostname or "").lower().strip()
    url = raw.lower().rstrip("/") if has_scheme else ""
    return host, url


def _strip_port_host(pattern: str) -> str:
    p = pattern.strip().lower()
    if "://" in p:
        p = urlparse(p).hostname or ""
    if ":" in p and "/" not in p:
        p = p.split(":", 1)[0]
    return p.strip().strip(".")


def _split_host_port(pattern: str) -> Tuple[str, Optional[int]]:
    """Split a bare ``host[:port]`` pattern into its host and optional port.

    A pattern that pins a port must be honoured: an excluded
    ``admin.example.com:8443`` has to keep excluding that target even though the
    target carries a port, otherwise the exclusion is silently bypassed.
    """
    p = pattern.strip().lower()
    if "://" in p:
        parsed = urlparse(p)
        return (parsed.hostname or "").strip("."), parsed.port
    if "/" in p:
        p = p.split("/", 1)[0]
    if ":" in p:
        host, _, port = p.partition(":")
        try:
            return host.strip("."), int(port)
        except ValueError:
            return host.strip("."), None
    return p.strip("."), None


def _target_host_port(target: str) -> Tuple[str, Optional[int]]:
    """Return the host and explicit port of a target (``None`` when absent)."""
    raw = (target or "").strip()
    if not raw:
        return "", None
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or "").lower().strip("."), parsed.port


def _port_agrees(pattern_port: Optional[int], target: str) -> bool:
    """Does a pattern's pinned port agree with the target's port?

    A pattern with no port matches any port.  A pattern that pins a port
    requires the target to be on that port; a target with no explicit port only
    matches a pinned default port (80/443), which keeps the check conservative.
    """
    if pattern_port is None:
        return True
    _, target_port = _target_host_port(target)
    if target_port is None:
        return pattern_port in (80, 443)
    return target_port == pattern_port


def host_matches(pattern: str, host: str) -> bool:
    """Does a host pattern cover ``host``?

    Supported forms:

    ``example.com``        exact host (and its ``www.`` variant)
    ``*.example.com``      any sub-domain, but *not* the apex itself
    ``api.example.com``    exact host
    """
    if not pattern or not host:
        return False
    pat = _strip_port_host(pattern)
    if not pat:
        return False
    host = host.lower().strip().strip(".")

    if pat.startswith("*."):
        base = pat[2:]
        return host.endswith("." + base) and host != base
    if pat.startswith("*"):
        return fnmatch.fnmatch(host, pat)

    if host == pat:
        return True
    # A bare apex most programs intend to include the www host.
    if host == "www." + pat:
        return True
    return False


def url_matches(pattern: str, url: str) -> bool:
    """URL-prefix match (used when a scope entry is a full URL)."""
    if not pattern or not url:
        return False
    pat = pattern.strip().lower().rstrip("/")
    return url.lower().rstrip("/").startswith(pat)


def target_matches_pattern(target: str, pattern: str) -> bool:
    """Match a raw scope pattern (host, glob or URL) against a target."""
    host, url = normalize_target(target)
    if not host and not url:
        return False

    pat = (pattern or "").strip()
    if not pat:
        return False

    if "://" in pat:
        # Full URL entry: require scheme+host+path prefix agreement.
        if url:
            return url_matches(pat, url)
        pat_host = urlparse(pat).hostname or ""
        return host_matches(pat_host, host) and _port_agrees(urlparse(pat).port, target)

    if "/" in pat:
        # host/path entry
        pat_host, _, _ = pat.partition("/")
        return host_matches(pat_host, host) and (not url or url.startswith(pat.lower()))

    # Bare host, host:port or glob.
    if _HOST_RE.match(pat) or pat.startswith("*"):
        return host_matches(pat, host)

    # A bare host:port pattern (e.g. an excluded "admin.example.com:8443").
    pat_host, pat_port = _split_host_port(pat)
    if pat_host and (pat_port is not None or _HOST_RE.match(pat_host)):
        return host_matches(pat_host, host) and _port_agrees(pat_port, target)

    return False


def match_exclusion(target: str, rule: OutOfScopeRule) -> bool:
    """Does an out-of-scope rule apply to ``target``?"""
    if rule.kind == "technique":
        return False  # handled separately by the authorizer
    return target_matches_pattern(target, rule.pattern)


def resolve_scope(
    target: str,
    scope: ProgramScope,
) -> Tuple[bool, Optional[ScopeTarget], Optional[OutOfScopeRule]]:
    """Resolve a target against a program scope.

    Returns ``(in_scope, matched_in_scope_entry, matched_exclusion)``.

    Exclusions are evaluated **first** and always win — a target that is both
    listed in scope and excluded is treated as out of scope.
    """
    for rule in scope.out_of_scope:
        if match_exclusion(target, rule):
            return False, None, rule
    for entry in scope.in_scope:
        if target_matches_pattern(target, entry.pattern):
            return True, entry, None
    return False, None, None


def technique_prohibited(technique_id: str, scope: ProgramScope) -> bool:
    """Is a technique forbidden by the program, regardless of scope match?"""
    tid = (technique_id or "").strip().lower()
    if not tid:
        return False
    prohibited = {t.strip().lower() for t in scope.prohibited_techniques}
    permitted = {t.strip().lower() for t in scope.permitted_techniques}
    if tid in permitted:
        return False
    return tid in prohibited
