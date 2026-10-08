"""agathon.defense.rule_memory — defense memory of verified Aegis rules.

Before the Brain fires a new attack, it can ask: "do we already have a verified
Aegis rule that blocks this payload class?" If yes, the strike is redundant —
the defense already covers it — so the orchestrator can skip it and log
``blocked_by_existing_rule``. This is the engine *remembering* it already
defended a vector, the defense-side analogue of EVOLVE_SYSTEM's attack lessons.

Verified rules are loaded once per scan (lazily) and cached in-memory; each new
payload is tested against the cached patterns with the same deterministic
matcher used by the live closed loop. Best-effort throughout.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from .closed_loop_match import rule_blocks_payload

log = logging.getLogger(__name__)


class RuleMemory:
    """Per-scan cache of verified Aegis rules + a payload matcher."""

    def __init__(self) -> None:
        self._loaded: bool = False
        self._rules: List[dict] = []

    def _load(self, supabase: Any, user_id: str) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            if not supabase:
                return
            # Verified + enabled rules only. Scope to the operator's scans via
            # the scan_id → user_id join would need an RPC; keep it simple and
            # pull the global verified set (rules are already user-scoped by RLS
            # at write time, and the engine uses the service role).
            resp = (
                supabase.table("aegis_rules")
                .select("rule_id,pattern,description")
                .eq("verified_blocks_attack", True)
                .eq("enabled", True)
                .limit(200)
                .execute()
            )
            self._rules = list(getattr(resp, "data", None) or [])
        except Exception as exc:  # noqa: BLE001
            log.warning("[rule_memory] load failed (degraded): %s", exc)
            self._rules = []

    def matches_existing_verified_rule(
        self,
        attack_payload: Any,
        attack_name: str,
        supabase: Any,
        user_id: str = "",
    ) -> Optional[dict]:
        """Return the first verified rule that blocks this payload, else None."""
        try:
            self._load(supabase, user_id)
            for rule in self._rules:
                pattern = str(rule.get("pattern") or "")
                if not pattern:
                    continue
                if rule_blocks_payload(pattern, None, attack_payload, attack_name):
                    return rule
        except Exception as exc:  # noqa: BLE001
            log.warning("[rule_memory] match failed (degraded): %s", exc)
        return None

    @property
    def rule_count(self) -> int:
        return len(self._rules)
