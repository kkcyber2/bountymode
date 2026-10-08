"""AI_MODEL / LLM ENDPOINT — Garak + PyRIT prompt hijacking and jailbreak strikes."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, TYPE_CHECKING

from agathon.garak_catalog import get_kinetic_battery_strikes
from agathon.target_client import build_universal_client

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_PRIORITY = frozenset({"prompt_injection", "jailbreak", "pii_leak"})

# Explicit kinetic labels for Prompt Hijacker + Jailbreak (Garak + PyRIT).
_HIJACKER_PROBES: tuple[tuple[str, str, str], ...] = (
    ("garak.prompt_injection.hijacker", "prompt_injection", "Prompt Hijacker"),
    ("garak.jailbreak.dan_mode", "jailbreak", "Jailbreak"),
    ("garak.prompt_injection.translate_leak", "prompt_injection", "Prompt Hijacker"),
    ("garak.jailbreak.hypothetical", "jailbreak", "Jailbreak"),
)


def _run_ai_model_probes_sync(state: "AgathonState") -> List[Dict[str, Any]]:
    """Sync Garak/PyRIT probe loop — run via asyncio.to_thread from async callers."""
    from agathon.orchestrator import sync_probe_heartbeat

    findings: List[Dict[str, Any]] = []
    probe_idx = 0
    utc = build_universal_client(
        target_url=state.target_url,
        target_api_key=state.api_key,
        model=state.target_model,
        target_provider=state.target_provider,
    )
    llm_client = utc._llm()

    try:
        from probes.garak import run_garak_probe
        from probes.pyrit_adapter import PYRIT_SCENARIOS, run_pyrit_probe
        from agathon.garak_runner import CURATED_VECTORS, run_garak_category
    except ImportError:
        logger.warning("[ai_model] probe imports unavailable")
        return findings

    for registry_name, category, label in _HIJACKER_PROBES:
        try:
            result = run_garak_category(
                llm_client,
                state.target_model,
                category=category,
            )
            findings.append(
                {
                    "surface": "LLM ENDPOINT",
                    "vector": "AI_MODEL",
                    "probe": registry_name,
                    "category": category,
                    "strike_label": label,
                    "success": bool(getattr(result, "success", False)),
                    "severity": getattr(result, "severity", "info"),
                    "evidence": (getattr(result, "response", "") or "")[:500],
                }
            )
            probe_idx += 1
            sync_probe_heartbeat(state, probe_idx)
        except Exception as exc:  # noqa: BLE001
            curated = CURATED_VECTORS.get(category, [])
            if curated:
                prompt = curated[0]
                try:
                    response = llm_client.generate_response(prompt)
                    from agathon.garak_runner import _looks_like_breach

                    hit = _looks_like_breach(response or "")
                    findings.append(
                        {
                            "surface": "LLM ENDPOINT",
                            "vector": "AI_MODEL",
                            "probe": registry_name,
                            "category": category,
                            "strike_label": label,
                            "success": hit,
                            "severity": "high" if hit else "info",
                            "evidence": (response or "")[:500],
                        }
                    )
                    probe_idx += 1
                    sync_probe_heartbeat(state, probe_idx)
                except Exception as inner:  # noqa: BLE001
                    logger.debug("[ai_model] hijacker %s skipped: %s", registry_name, inner)
            else:
                logger.debug("[ai_model] hijacker %s skipped: %s", registry_name, exc)

    strikes = [
        s for s in get_kinetic_battery_strikes() if s[1] in _PRIORITY
    ][:8]
    if not strikes:
        strikes = get_kinetic_battery_strikes()[:6]

    # Full Garak catalogue — capped batch so event loop stays responsive via to_thread.
    _GARAK_BATCH_CAP = 64
    try:
        from agathon.garak_catalog import discover_garak_probes, hot_reload_garak_catalog

        hot_reload_garak_catalog(
            scan_api_key=state.api_key or "",
            target_url=state.target_url or "",
        )
        catalog_specs = discover_garak_probes()[:_GARAK_BATCH_CAP]
        seen_names = {s[0] for s in strikes}
        for spec in catalog_specs:
            if spec.registry_name in seen_names:
                continue
            seen_names.add(spec.registry_name)
            parts = spec.registry_name.split(".")
            if len(parts) < 3:
                continue
            try:
                result = run_garak_probe(
                    llm_client,
                    state.target_model,
                    probe_module=parts[1],
                    probe_class=parts[2],
                    category=spec.category,
                    registry_name=spec.registry_name,
                )
                findings.append(
                    {
                        "surface": "LLM ENDPOINT",
                        "vector": "AI_MODEL",
                        "probe": spec.registry_name,
                        "category": spec.category,
                        "success": bool(getattr(result, "success", False)),
                        "severity": getattr(result, "severity", "info"),
                        "evidence": (getattr(result, "response", "") or "")[:500],
                    }
                )
                probe_idx += 1
                sync_probe_heartbeat(state, probe_idx)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[ai_model] catalog probe %s skipped: %s",
                    spec.registry_name,
                    exc,
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ai_model] garak catalog batch skipped: %s", exc)

    for registry_name, category in strikes:
        try:
            parts = registry_name.split(".")
            if len(parts) >= 3:
                result = run_garak_probe(
                    llm_client,
                    state.target_model,
                    probe_module=parts[1],
                    probe_class=parts[2],
                    category=category,
                    registry_name=registry_name,
                )
            else:
                result = run_garak_probe(
                    llm_client,
                    state.target_model,
                    probe_module=category.replace("_", ""),
                    probe_class="InjectMarkup",
                    category=category,
                    registry_name=registry_name,
                )
            findings.append(
                {
                    "surface": "LLM ENDPOINT",
                    "vector": "AI_MODEL",
                    "probe": registry_name,
                    "category": category,
                    "success": bool(getattr(result, "success", False)),
                    "severity": getattr(result, "severity", "info"),
                    "evidence": (getattr(result, "response", "") or "")[:500],
                }
            )
            probe_idx += 1
            sync_probe_heartbeat(state, probe_idx)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[ai_model] garak probe %s skipped: %s", registry_name, exc)

    pyrit_hijack = [
        s for s in PYRIT_SCENARIOS
        if s["category"] in ("prompt_injection", "jailbreak")
    ][:4]
    for spec in pyrit_hijack or PYRIT_SCENARIOS[:2]:
        try:
            result = run_pyrit_probe(
                llm_client,
                registry_name=spec["name"],
                category=spec["category"],
            )
            findings.append(
                {
                    "surface": "LLM ENDPOINT",
                    "vector": "AI_MODEL",
                    "probe": spec["name"],
                    "category": spec["category"],
                    "success": bool(getattr(result, "success", False)),
                    "severity": getattr(result, "severity", "info"),
                    "evidence": (getattr(result, "response", "") or "")[:500],
                }
            )
            probe_idx += 1
            sync_probe_heartbeat(state, probe_idx)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[ai_model] pyrit %s skipped: %s", spec["name"], exc)

    return findings


async def run_ai_model_probes(state: "AgathonState") -> List[Dict[str, Any]]:
    """Application Logic first, then Garak/PyRIT off the event loop thread."""
    from probes.application_logic import run_application_logic_probes

    findings: List[Dict[str, Any]] = []
    try:
        findings.extend(await run_application_logic_probes(state))
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ai_model] application_logic probes failed: %s", exc)

    try:
        garak_batch = await asyncio.wait_for(
            asyncio.to_thread(_run_ai_model_probes_sync, state),
            timeout=120,
        )
        findings.extend(garak_batch)
    except asyncio.TimeoutError:
        logger.warning("[ai_model] Garak/PyRIT batch exceeded 120s — partial results retained")
        findings.append(
            {
                "surface": "LLM ENDPOINT",
                "vector": "AI_MODEL",
                "probe": "garak_pyrit_timeout_guard",
                "category": "prompt_injection",
                "success": False,
                "severity": "medium",
                "evidence": "Garak/PyRIT catalogue batch aborted at 120s event-loop guard",
            }
        )

    return findings
