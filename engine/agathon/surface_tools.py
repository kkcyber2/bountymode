"""agathon.surface_tools — Brain-callable tools for non-LLM surfaces.

The LLM surface gets the full kinetic + catalogue attack pipeline via
``run_attack``. Non-LLM surfaces (web / code / mobile) previously ran a single
batch of kinetic vectors and auto-sealed with *no Brain reasoning*. This module
exposes the existing surface probes as individual Brain tools so the Brain can
reason about, pivot between, and re-run them just like LLM attacks.

Each tool runs the relevant probe (in a worker thread — Playwright + httpx are
blocking), folds results into ``state.findings`` + ``scan_logs``, and returns a
compact verdict dict for the Brain's tool message. Best-effort throughout: a
probe failure returns an empty list, never raises into the Brain loop.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Auth + finding fold helpers                                                  #
# --------------------------------------------------------------------------- #


def _surface_auth_header(state: Any) -> str:
    try:
        from agathon.target_client import build_universal_client

        url = state.target_url
        if not url.startswith("http"):
            url = f"https://{url}"
        utc = build_universal_client(
            target_url=url,
            target_api_key=state.api_key,
            model=state.target_model,
            target_provider=state.target_provider,
        )
        return utc.authorization_header() or ""
    except Exception as exc:  # noqa: BLE001
        log.warning("[surface_tools] auth header build failed: %s", exc)
        return ""


def _target_url(state: Any) -> str:
    url = state.target_url or ""
    if url and not url.startswith("http"):
        url = f"https://{url}"
    return url


def _sev_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        (sev or "info").lower(), 0
    )


async def _fold_surface_findings(
    state: Any,
    *,
    probe_name: str,
    family: str,
    surface: str,
    raw: List[Dict[str, Any]],
    emit_log: Any,
) -> Dict[str, Any]:
    """Normalize probe findings into the orchestrator finding shape + emit logs."""
    breaches = 0
    top_sev = "info"
    for f in raw or []:
        sev = str(f.get("severity") or "info").lower()
        success = bool(f.get("success"))
        if _sev_rank(sev) > _sev_rank(top_sev):
            top_sev = sev
        if success and sev != "info":
            breaches += 1
        finding = {
            "attack": probe_name,
            "family": family,
            "level": "hard",
            "severity": sev,
            "rationale": f"{surface} surface probe",
            "payload": {
                "success": success,
                "severity": sev,
                "summary": str(f.get("evidence") or f.get("summary") or "")[:600],
                "probe": str(f.get("probe") or probe_name),
                "category": family,
                "response_excerpt": str(f.get("evidence") or "")[:400],
            },
            "ts": time.time(),
        }
        state.findings.append(finding)
        state.attacks_run += 1
        await emit_log(
            state,
            log_type="breach" if (success and sev != "info") else "strike",
            severity=sev,
            attack_name=probe_name,
            payload=finding["payload"],
        )
    return {
        "ok": True,
        "probe": probe_name,
        "surface": surface,
        "family": family,
        "findings": len(raw or []),
        "breaches": breaches,
        "top_severity": top_sev,
        "verdict": breaches > 0,
    }


# --------------------------------------------------------------------------- #
# Web surface                                                                  #
# --------------------------------------------------------------------------- #


async def run_xss_probe(state: Any, emit_log: Any) -> Dict[str, Any]:
    from probes.web_app import _xss_sqli_scout_sync

    url = _target_url(state)
    auth = _surface_auth_header(state)
    raw = await asyncio.to_thread(_xss_sqli_scout_sync, url, auth)
    return await _fold_surface_findings(
        state, probe_name="web.xss_sqli_scout", family="web_xss",
        surface="WEB APPLICATION", raw=raw, emit_log=emit_log,
    )


async def discover_hidden_paths(state: Any, emit_log: Any) -> Dict[str, Any]:
    from probes.web_app import _logic_discovery_sync

    url = _target_url(state)
    auth = _surface_auth_header(state)
    raw = await asyncio.to_thread(_logic_discovery_sync, url, auth)
    return await _fold_surface_findings(
        state, probe_name="web.logic_discovery", family="web_logic",
        surface="WEB APPLICATION", raw=raw, emit_log=emit_log,
    )


async def audit_security_headers(state: Any, emit_log: Any) -> Dict[str, Any]:
    """Check the target URL for missing security headers (no Playwright needed)."""
    import httpx

    url = _target_url(state)
    headers = {"Authorization": _surface_auth_header(state)} if _surface_auth_header(state) else {}
    missing: List[str] = []
    findings: List[Dict[str, Any]] = []
    try:
        def _fetch() -> Dict[str, str]:
            with httpx.Client(timeout=15.0, follow_redirects=True) as c:
                r = c.get(url, headers=headers)
                return dict(r.headers)
        hdrs = await asyncio.to_thread(_fetch)
        required = [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
        ]
        lower = {k.lower(): v for k, v in hdrs.items()}
        missing = [h for h in required if h not in lower]
        sev = "medium" if missing else "info"
        findings.append({
            "probe": "security_headers",
            "success": bool(missing),
            "severity": sev,
            "evidence": f"missing headers: {', '.join(missing) or 'none'}",
        })
    except Exception as exc:  # noqa: BLE001
        findings.append({
            "probe": "security_headers", "success": False, "severity": "info",
            "evidence": f"fetch failed: {exc}"[:200],
        })
    return await _fold_surface_findings(
        state, probe_name="web.security_headers", family="web_headers",
        surface="WEB APPLICATION", raw=findings, emit_log=emit_log,
    )


# --------------------------------------------------------------------------- #
# Code / API gateway surface                                                   #
# --------------------------------------------------------------------------- #


async def run_bola_fuzzer(state: Any, emit_log: Any) -> Dict[str, Any]:
    from probes.api_gateway import _run_api_gateway_probes_sync

    raw = await asyncio.to_thread(_run_api_gateway_probes_sync, state)
    return await _fold_surface_findings(
        state, probe_name="code.bola_idor_fuzzer", family="api_bola",
        surface="API GATEWAY", raw=raw, emit_log=emit_log,
    )


# --------------------------------------------------------------------------- #
# Mobile / chatbot surface                                                     #
# --------------------------------------------------------------------------- #


async def probe_intent_drift(state: Any, emit_log: Any) -> Dict[str, Any]:
    from probes.chat_bot import _run_chat_bot_probes_sync

    raw = await asyncio.to_thread(_run_chat_bot_probes_sync, state)
    # Tag the first half as intent-drift, second half as tool-injection so the
    # Brain sees two distinct tools over the same probe battery.
    half = max(1, len(raw) // 2)
    return await _fold_surface_findings(
        state, probe_name="mobile.intent_drift", family="chatbot_intent",
        surface="CHAT BOT", raw=raw[:half], emit_log=emit_log,
    )


async def probe_tool_injection(state: Any, emit_log: Any) -> Dict[str, Any]:
    from probes.chat_bot import _run_chat_bot_probes_sync

    raw = await asyncio.to_thread(_run_chat_bot_probes_sync, state)
    half = max(1, len(raw) // 2)
    return await _fold_surface_findings(
        state, probe_name="mobile.tool_injection", family="chatbot_tool_injection",
        surface="CHAT BOT", raw=raw[half:], emit_log=emit_log,
    )


# --------------------------------------------------------------------------- #
# Tool registry per surface                                                    #
# --------------------------------------------------------------------------- #


SURFACE_TOOLS: Dict[str, Dict[str, Any]] = {
    "web": {
        "run_xss_probe": run_xss_probe,
        "discover_hidden_paths": discover_hidden_paths,
        "audit_security_headers": audit_security_headers,
    },
    "code": {
        "run_bola_fuzzer": run_bola_fuzzer,
    },
    "mobile": {
        "probe_intent_drift": probe_intent_drift,
        "probe_tool_injection": probe_tool_injection,
    },
}


def surface_tool_names(surface_kind: str) -> List[str]:
    kind = (surface_kind or "llm").strip().lower()
    return list(SURFACE_TOOLS.get(kind, {}).keys())


def surface_tool_schemas(surface_kind: str) -> List[Dict[str, Any]]:
    """OpenAI-style tool schemas for the surface's Brain tools."""
    descriptions: Dict[str, str] = {
        "run_xss_probe": "Run the XSS + SQLi reflection scout against the web target.",
        "discover_hidden_paths": "Discover hidden/logic-discovery routes on the web target.",
        "audit_security_headers": "Audit the web target for missing security headers (HSTS, CSP, etc.).",
        "run_bola_fuzzer": "Run the BOLA/IDOR sequential fuzzer against the API gateway.",
        "probe_intent_drift": "Probe the chatbot for intent drift away from its declared scope.",
        "probe_tool_injection": "Probe the chatbot for tool-call injection / parameter hijack.",
    }
    out: List[Dict[str, Any]] = []
    for name in surface_tool_names(surface_kind):
        out.append({
            "type": "function",
            "function": {
                "name": name,
                "description": descriptions.get(name, name),
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        })
    return out


async def dispatch_surface_tool(
    state: Any, name: str, emit_log: Any
) -> Dict[str, Any]:
    kind = (state.surface_kind or "llm").strip().lower()
    fn = SURFACE_TOOLS.get(kind, {}).get(name)
    if fn is None:
        return {"ok": False, "error": f"unknown surface tool '{name}' for surface '{kind}'"}
    try:
        return await fn(state, emit_log)
    except Exception as exc:  # noqa: BLE001
        log.warning("[surface_tools] %s failed: %s", name, exc)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
