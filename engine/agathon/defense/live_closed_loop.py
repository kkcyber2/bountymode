"""agathon.defense.live_closed_loop — live Aegis defense evolution mid-scan.

When a breach is detected *during* a scan, the judge already produces a
``remediation_code_snippet`` (an Aegis regex / WAF rule / middleware snippet).
Instead of waiting until seal to generate defense and verifying it manually on
the frontend, this module:

1. Takes the breach finding + judge remediation snippet.
2. Normalizes the snippet into a rule (Cloudflare expression or regex).
3. Re-fires the *same* attack payload body against that rule locally
   (deterministic proof — no live target contact).
4. Returns ``Blocked`` / ``NotBlocked`` / ``RuleInvalid`` so the orchestrator
   can mark the rule verified and feed "blocked" back into the EVOLVE_SYSTEM.

This is the defense half of self-evolution: the engine proves in real time that
the defense it just invented actually stops the attack that triggered it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .closed_loop_match import rule_blocks_payload

log = logging.getLogger(__name__)


@dataclass
class ClosedLoopResult:
    technique: str
    blocked: bool
    rule_text: str
    reason: str = ""
    duration_ms: float = 0.0

    @property
    def verdict(self) -> str:
        if self.blocked:
            return "Blocked"
        if self.reason == "rule_invalid":
            return "RuleInvalid"
        return "NotBlocked"


def _technique_for_attack(attack_name: str) -> str:
    """Stable technique slug embedded in Aegis rule_ids (fg-aegis-<technique>-...)."""
    name = (attack_name or "").strip().lower()
    if not name:
        return "generic"
    # Use the family prefix (everything before the first dot) as the technique.
    return name.split(".")[0].replace("_", "-")[:40] or "generic"


def _normalize_rule(snippet: str, attack_name: str) -> str:
    """Build a best-effort Cloudflare-style expression from a remediation snippet.

    If the snippet already contains a ``http.request.body.raw ...`` clause we
    keep it as-is; otherwise we wrap any regex literal found in the snippet into
    a body-matches clause so the matcher can evaluate it. Falls back to an
    expression that contains the raw snippet text.
    """
    snippet = (snippet or "").strip()
    if not snippet:
        return ""
    if "http.request.body.raw" in snippet.lower():
        return snippet
    # Extract the first regex literal r"..." / "..." from the snippet.
    import re

    m = re.search(r'r"((?:[^"\\]|\\.)*)"', snippet)
    if m and m.group(1).strip():
        return f'http.request.body.raw matches r"{m.group(1)}"'
    m = re.search(r'"([^"]{4,})"', snippet)
    if m and m.group(1).strip():
        return f'http.request.body.raw contains "{m.group(1)}"'
    return snippet  # last resort: feed raw snippet to the snippet matcher


def verify_rule_blocks_attack(
    rule: str, attack_payload: Any, attack_name: str, snippet: Optional[str] = None
) -> ClosedLoopResult:
    """Deterministic local proof: would ``rule`` block the attack payload body?"""
    technique = _technique_for_attack(attack_name)
    start = time.time()
    rule_text = _normalize_rule(rule or snippet or "", attack_name)
    if not rule_text:
        return ClosedLoopResult(
            technique=technique, blocked=False, rule_text="", reason="rule_invalid",
            duration_ms=(time.time() - start) * 1000,
        )
    blocked = rule_blocks_payload(rule_text, snippet, attack_payload, attack_name)
    return ClosedLoopResult(
        technique=technique,
        blocked=blocked,
        rule_text=rule_text[:500],
        reason="" if blocked else "not_blocked",
        duration_ms=(time.time() - start) * 1000,
    )


def evolve_and_apply(breach_finding: Dict[str, Any]) -> ClosedLoopResult:
    """Take a breach finding (with judge remediation) and prove the rule live.

    ``breach_finding`` is the orchestrator finding dict — it must carry the
    attack payload (``payload``) and, ideally, the judge's
    ``remediation_code_snippet``. The attack payload body is reconstructed from
    ``payload.payload_used`` / ``payload.prompt`` / the finding ``payload``.
    """
    attack_name = str(breach_finding.get("attack") or "")
    payload_obj = breach_finding.get("payload") or {}
    snippet = None
    attack_body: Any = payload_obj

    if isinstance(payload_obj, dict):
        snippet = (
            payload_obj.get("remediation_code_snippet")
            or payload_obj.get("remediation")
            or breach_finding.get("remediation_code_snippet")
        )
        # Prefer the exact input that triggered the breach.
        attack_body = (
            payload_obj.get("payload_used")
            or payload_obj.get("prompt")
            or payload_obj.get("payload")
            or payload_obj.get("response_excerpt")
            or payload_obj
        )

    rule = breach_finding.get("rule") or breach_finding.get("pattern") or snippet
    return verify_rule_blocks_attack(
        rule=rule or "",
        attack_payload=attack_body,
        attack_name=attack_name,
        snippet=snippet,
    )
