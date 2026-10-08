"""
Global Precision Pacing — shared Groq 429 backoff across orchestrator + kinetic modules.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from .orchestrator import AgathonState

log = logging.getLogger("agathon.pacing_lock")

PRECISION_PACING_DELAY_S = 10.0
PRECISION_PACING_ATTEMPTS = 5

# Worker-wide lock — one scan hitting 429 slows all Groq callers briefly.
_global_lock: Dict[str, Any] = {"remaining": 0, "delay_s": PRECISION_PACING_DELAY_S}


def is_groq_rate_limit_text(text: str) -> bool:
    t = (text or "").lower()
    return (
        "[http-429]" in t
        or "429" in t
        or "rate limit" in t
        or "too many requests" in t
        or "tpm" in t
        or "tokens per minute" in t
    )


def activate_global_pacing_lock(state: Optional["AgathonState"] = None) -> None:
    """On Groq 429 — fixed 10s delay for the next 5 probe/brain pauses."""
    _global_lock["remaining"] = PRECISION_PACING_ATTEMPTS
    _global_lock["delay_s"] = PRECISION_PACING_DELAY_S
    if state is not None:
        state.sovereign_probe_delay_s = PRECISION_PACING_DELAY_S
        state.pacing_lock_remaining = PRECISION_PACING_ATTEMPTS


def effective_pacing_delay_s(state: Optional["AgathonState"] = None) -> float:
    if _global_lock["remaining"] > 0:
        return float(_global_lock["delay_s"])
    if state is not None and int(getattr(state, "pacing_lock_remaining", 0) or 0) > 0:
        return PRECISION_PACING_DELAY_S
    if state is not None:
        return float(getattr(state, "sovereign_probe_delay_s", 5.0) or 5.0)
    return 5.0


def consume_pacing_lock(state: Optional["AgathonState"] = None) -> None:
    if _global_lock["remaining"] > 0:
        _global_lock["remaining"] -= 1
    if state is not None and int(getattr(state, "pacing_lock_remaining", 0) or 0) > 0:
        state.pacing_lock_remaining -= 1


async def precision_pacing_pause(state: Optional["AgathonState"] = None) -> None:
    delay = effective_pacing_delay_s(state)
    consume_pacing_lock(state)
    await asyncio.sleep(delay)
