"""Read the engine's live attack catalogue.

The engine exposes its full arsenal as a module-level ``REGISTRY`` list of
entries shaped ``{"name", "family", "level", "fn"}``.  That list is assembled at
import time from three sources:

* the hand-written families in ``forgeguard_bridge`` (prompt injection, data
  exfiltration, ...),
* the Garak probe wrappers, and
* the auto-discovered ``agathon/plugins`` (direct injection, autodan, paIR,
  TAP, many-shot, tool-shadowing, tool-pivot, second-order RAG, leak harvester).

This module reads that registry without duplicating it, so the catalogue can
never drift from the engine.  Loading is lazy and failure-tolerant: if the
engine is absent or one of its optional dependencies is missing, the rest of
Bounty Mode keeps working and :meth:`EngineCatalogue.available` reports False.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional

from .paths import engine_available, ensure_on_path, quiet_engine_boot

log = logging.getLogger(__name__)


class EngineCatalogue:
    """A read-only view over the engine's ``REGISTRY``."""

    def __init__(self) -> None:
        self._entries: Optional[List[Dict[str, Any]]] = None
        self._error: str = ""

    # -- loading ----------------------------------------------------------- #

    def _load(self) -> List[Dict[str, Any]]:
        if self._entries is not None:
            return self._entries
        if not engine_available():
            self._error = "engine directory not found"
            self._entries = []
            return self._entries
        try:
            ensure_on_path()
            with quiet_engine_boot():
                import forgeguard_bridge  # type: ignore  # engine module
            entries = list(getattr(forgeguard_bridge, "REGISTRY", []) or [])
            self._entries = entries
            log.info("[engine] catalogue loaded: %d techniques", len(entries))
        except Exception as exc:  # noqa: BLE001 - never break the workflow layer
            self._error = f"{type(exc).__name__}: {exc}"
            log.warning("[engine] catalogue unavailable: %s", self._error)
            self._entries = []
        return self._entries

    # -- queries ----------------------------------------------------------- #

    @property
    def error(self) -> str:
        self._load()
        return self._error

    def available(self) -> bool:
        return bool(self._load())

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._load())

    def names(self) -> List[str]:
        return [e.get("name", "") for e in self._load() if e.get("name")]

    def families(self) -> List[str]:
        seen: List[str] = []
        for e in self._load():
            fam = e.get("family", "")
            if fam and fam not in seen:
                seen.append(fam)
        return sorted(seen)

    def levels(self) -> List[str]:
        seen: List[str] = []
        for e in self._load():
            lvl = e.get("level", "")
            if lvl and lvl not in seen:
                seen.append(lvl)
        return sorted(seen)

    def resolve(self, key: str) -> Optional[Dict[str, Any]]:
        """Find the catalogue entry that best matches ``key``.

        Resolution order, most specific first:

        1. exact ``name`` (``"prompt_injection"``, ``"garak.jailbreak"``),
        2. exact ``family`` (``"prompt_injection"``, ``"agent_hijack"``),
        3. dotted-prefix (``"agent_hijack"`` -> ``"agent_hijack.tool_pivot"``).

        A dotted prefix is resolved deterministically (shortest name, then
        lexicographic) so the same key always yields the same technique.
        """
        if not key:
            return None
        entries = self._load()

        for e in entries:
            if e.get("name") == key:
                return e

        for e in entries:
            if e.get("family") == key:
                return e

        candidates = [e for e in entries if str(e.get("name", "")).startswith(key + ".")]
        if candidates:
            candidates.sort(key=lambda e: (len(str(e.get("name"))), str(e.get("name"))))
            return candidates[0]
        return None

    def by_family(self, family: str) -> List[Dict[str, Any]]:
        return [e for e in self._load() if e.get("family") == family]

    def describe(self) -> List[Dict[str, Any]]:
        """Compact, JSON-safe description of the whole arsenal."""
        return [
            {
                "name": e.get("name", ""),
                "family": e.get("family", ""),
                "level": e.get("level", ""),
            }
            for e in self._load()
        ]

    def stats(self) -> Dict[str, Any]:
        entries = self._load()
        return {
            "available": bool(entries),
            "error": self._error,
            "techniques": len(entries),
            "families": len(self.families()),
            "levels": self.levels(),
        }


@lru_cache(maxsize=1)
def default_catalogue() -> EngineCatalogue:
    """Process-wide catalogue instance."""
    return EngineCatalogue()
