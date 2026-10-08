"""
Kinetic vector dispatch — four surface kinds (probes/ at repo root).

  llm    -> probes.ai_model      (Garak + PyRIT Prompt Hijacker / Jailbreak)
  web    -> probes.web_app       (Playwright XSS + Logic Discovery)
  code   -> probes.api_gateway    (BOLA/IDOR sequential fuzzer)
  mobile -> probes.chat_bot       (Intent Drift + Tool-Call Injection)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, TYPE_CHECKING

from probes.garak import MAX_PROBES_PER_STRIKE, probe_count, run_garak_probe
from probes.pyrit_adapter import PYRIT_PROBE_COUNT, extend_registry_with_pyrit, run_pyrit_probe

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_SURFACE_MAP = {
    "llm": "ai_model",
    "web": "web_app",
    "code": "api_gateway",
    "mobile": "chat_bot",
}


async def run_surface_probe(surface_kind: str, state: "AgathonState") -> List[Dict[str, Any]]:
    """Dispatch probes by UI surface_kind (llm/web/code/mobile)."""
    kind = (surface_kind or "llm").strip().lower()
    mapped = _SURFACE_MAP.get(kind, "ai_model")

    if mapped == "ai_model":
        from probes.ai_model import run_ai_model_probes

        return await run_ai_model_probes(state)
    if mapped == "web_app":
        from probes.web_app import run_web_app_probes

        return await run_web_app_probes(state)
    if mapped == "api_gateway":
        from probes.api_gateway import run_api_gateway_probes

        return await run_api_gateway_probes(state)
    if mapped == "chat_bot":
        from probes.chat_bot import run_chat_bot_probes

        return await run_chat_bot_probes(state)

    logger.warning("[probes] unknown surface_kind=%s — defaulting to AI_MODEL", kind)
    from probes.ai_model import run_ai_model_probes

    return await run_ai_model_probes(state)


__all__ = [
    "MAX_PROBES_PER_STRIKE",
    "PYRIT_PROBE_COUNT",
    "extend_registry_with_pyrit",
    "probe_count",
    "run_garak_probe",
    "run_pyrit_probe",
    "run_surface_probe",
]
