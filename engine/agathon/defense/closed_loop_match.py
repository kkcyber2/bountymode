"""agathon.defense.closed_loop_match — pure local proof matcher.

Python port of ``forgeguard-ai/src/lib/aegis/closed-loop-match.ts`` so the
engine and the frontend agree on what "the rule blocks this payload" means.

No network, no live target — this is a deterministic string/regex proof used
by the live Aegis closed loop to verify a generated defense rule would have
blocked the exact attack payload that just breached the target.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

# http.request.body.raw contains "LIT"
_LITERAL_RE = re.compile(
    r'http\.request\.body\.raw\s+contains\s+"((?:[^"\\]|\\.)*)"',
    re.IGNORECASE,
)
# http.request.body.raw matches r"REGEX"
_REGEX_RE = re.compile(
    r'http\.request\.body\.raw\s+matches\s+r"((?:[^"\\]|\\.)*)"',
    re.IGNORECASE,
)
# Generic quoted regexes inside snippets: r"..." / re.compile("...")
_SNIPPET_REGEX_RE = re.compile(
    r'(?:r|"|\'|re\.compile\(["\'])([^"\'\\]+?)["\']',
    re.IGNORECASE,
)


def payload_to_body(payload: Any, attack_name: Optional[str]) -> str:
    """Coerce a scan_logs payload (jsonb) + attack_name into a searchable body string."""
    if payload is None:
        return attack_name or ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (int, float, bool)):
        return str(payload)
    try:
        return json.dumps(payload)
    except Exception:  # noqa: BLE001
        return str(payload)


def _unescape_literal(raw: str) -> str:
    return raw.replace('\\"', '"').replace("\\\\", "\\")


def expression_matches_body(expression: str, body: str) -> bool:
    """Evaluate the body clauses of a Cloudflare WAF expression against a body.

    ``http.request.body.raw contains "LIT"`` → case-insensitive substring match.
    ``http.request.body.raw matches r"REGEX"`` → Python regex test.
    Path clauses (``http.request.uri.path ...``) are intentionally ignored —
    the proof assumes the attack reaches an /api LLM endpoint in scope. Within
    a body group, literals/regexes are OR-joined, so any one match suffices.
    """
    if not body or not expression:
        return False
    lower = body.lower()

    for m in _LITERAL_RE.finditer(expression):
        lit = _unescape_literal(m.group(1))
        if lit and lit.lower() in lower:
            return True

    for m in _REGEX_RE.finditer(expression):
        src = m.group(1)
        if not src:
            continue
        try:
            if re.search(src, body):
                return True
        except re.error:
            continue

    return False


def snippet_blocks_body(snippet: str, body: str) -> bool:
    """Heuristic: does a remediation snippet (regex / middleware) block the body?

    Extracts candidate regex sources from the snippet and tests each against the
    body. Also falls back to checking whether any quoted literal in the snippet
    appears in the body. Best-effort — a malformed snippet simply returns False.
    """
    if not snippet or not body:
        return False

    for m in _SNIPPET_REGEX_RE.finditer(snippet):
        src = m.group(1).strip()
        if len(src) < 3:
            continue
        try:
            if re.search(src, body):
                return True
        except re.error:
            continue

    # Fallback: quoted literal tokens in the snippet present in the body.
    for m in re.finditer(r'"([^"]{4,})"', snippet):
        tok = m.group(1)
        if tok.lower() in body.lower():
            return True
    return False


def rule_blocks_payload(
    expression: str,
    snippet: Optional[str],
    payload: Any,
    attack_name: Optional[str],
) -> bool:
    """Core closed-loop proof. True when the rule would have blocked the payload."""
    body = payload_to_body(payload, attack_name)
    if expression_matches_body(expression or "", body):
        return True
    if snippet and snippet_blocks_body(snippet, body):
        return True
    return False
