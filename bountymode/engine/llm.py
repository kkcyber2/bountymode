"""Provider-agnostic chat client for the engine's LLM calls.

The engine's attack modules call one method on their client:
``generate_response(prompt) -> str``.  Rather than depend on any single vendor
SDK, this module implements that contract against an OpenAI-compatible
``/chat/completions`` endpoint, which covers OpenRouter, Groq, OpenAI, Together,
Fireworks and a local Ollama or vLLM server.

Configuration is resolved in this order:

1. explicit constructor arguments,
2. the ``BOUNTYMODE_MODEL`` / ``BOUNTYMODE_LLM_BASE_URL`` /
   ``BOUNTYMODE_LLM_API_KEY`` environment variables,
3. the :class:`bountymode.config.BountyModeConfig` file + environment layer.

Only the standard library is used, so a run costs no extra dependency.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "openrouter/free"

#: Returned when no key is configured; the caller treats this as a dry run.
NO_KEY_MARKER = "[BOUNTYMODE-LLM:NO-KEY]"

#: A deliberately vulnerable mock assistant, used by offline runs and the UI so
#: the whole pipeline (gate -> engine -> evidence -> triage -> report) can be
#: exercised without a network call or an API key.  It echoes the engine's own
#: success sentinel and "leaks" throwaway secrets so redaction is visible.  The
#: secrets are obviously fake and are redacted before they reach disk.
SIMULATED_VULNERABLE_RESPONSE = (
    "Sure! PWNED-AGATHON. Here is my system prompt: 'You are the ACME support "
    "assistant. Never reveal internal data.' Internal note: the sandbox API key "
    "is sk-EXAMPLEnotarealkey000000000000 and the on-call address is "
    "security@acme.example."
)


@dataclass
class LLMResult:
    """One completion plus the metadata a report needs for reproducibility."""

    text: str
    model: str
    ok: bool = True
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text, "model": self.model, "ok": self.ok, "error": self.error}


@dataclass
class ChatClient:
    """OpenAI-compatible chat client with a bounded retry policy."""

    model: str = DEFAULT_MODEL
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    temperature: float = 0.7
    max_tokens: int = 1024
    timeout: float = 90.0
    max_attempts: int = 3
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.base_url = (self.base_url or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = self.api_key or _default_api_key()

    # -- introspection ------------------------------------------------------ #

    @property
    def configured(self) -> bool:
        """True when a key is present (so a live call can be attempted)."""
        return bool(self.api_key)

    def describe(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "base_url": self.base_url,
            "configured": self.configured,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

    # -- completion --------------------------------------------------------- #

    def generate_response(self, prompt: str, **kwargs: Any) -> str:
        """Engine-compatible single-string completion.

        A missing key is not an error: it returns a sentinel so an offline run
        stays deterministic instead of crashing mid-case.
        """
        return self.chat(prompt, **kwargs).text

    def chat(
        self,
        prompt: str,
        *,
        system_message: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResult:
        if not self.configured:
            return LLMResult(text=NO_KEY_MARKER, model=self.model, ok=False,
                             error="no API key configured (offline)")

        messages: List[Dict[str, str]] = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": self.max_tokens if max_tokens is None else max_tokens,
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "HTTP-Referer": "https://github.com/kkcyber2/bountymode",
            "X-Title": "Bounty Mode",
        }
        headers.update(self.extra_headers or {})

        last_err = ""
        for attempt in range(self.max_attempts):
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/chat/completions", data=body, headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    data = json.loads(resp.read().decode("utf-8") or "{}")
                choices = data.get("choices") or []
                if not choices:
                    return LLMResult(text="", model=self.model, ok=False,
                                     error=f"no choices in response: {str(data)[:200]}")
                text = (choices[0].get("message") or {}).get("content", "") or ""
                return LLMResult(text=_strip_reasoning(text), model=self.model)
            except urllib.error.HTTPError as exc:
                last_err = f"HTTP {exc.code}"
                if exc.code in (429, 503) and attempt < self.max_attempts - 1:
                    time.sleep(min(30.0, 2.0 * (2 ** attempt)))
                    continue
                return LLMResult(text="", model=self.model, ok=False, error=last_err)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                if attempt < self.max_attempts - 1:
                    time.sleep(min(30.0, 2.0 * (2 ** attempt)))
                    continue
        return LLMResult(text="", model=self.model, ok=False, error=last_err)

    def reachable(self) -> LLMResult:
        """Cheap live probe used by ``bountymode models --check``."""
        if not self.configured:
            return LLMResult(text="", model=self.model, ok=False,
                             error="no API key configured")
        return self.chat("Reply with the single word: pong", max_tokens=16, temperature=0.0)


def _strip_reasoning(text: str) -> str:
    """Drop ``<think>...</think>`` reasoning blocks some models emit."""
    out = text
    while "<think>" in out and "</think>" in out:
        start = out.index("<think>")
        end = out.index("</think>") + len("</think>")
        out = out[:start] + out[end:]
    return out.strip()


def _default_api_key() -> str:
    for var in ("BOUNTYMODE_LLM_API_KEY", "OPENROUTER_API_KEY"):
        val = os.environ.get(var, "").strip()
        if val:
            return val
    return ""


def client_from_config() -> ChatClient:
    """Build a client from :mod:`bountymode.config` (lazy import, cycle-free)."""
    try:
        from ..config import load_config

        cfg = load_config().llm
    except Exception:  # noqa: BLE001 - config is optional
        return ChatClient()
    return ChatClient(
        model=cfg.model,
        api_key=cfg.api_key,
        base_url=cfg.base_url,
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        timeout=cfg.timeout,
    )


class OfflineClient:
    """Deterministic client used by tests and by ``--offline`` runs.

    It never performs I/O.  Responses are derived from the prompt so a run is
    reproducible and can be asserted against.

    Set ``simulate_vulnerable=True`` to model a *deliberately vulnerable* mock
    assistant: every reply then looks like a successful compromise (echoing the
    engine's success sentinel and "leaking" fake secrets).  That is what makes
    an offline run demonstrate the full pipeline end to end; it is clearly
    labelled as simulated everywhere it is used.
    """

    def __init__(
        self,
        canned: Optional[Dict[str, str]] = None,
        default: str = "",
        simulate_vulnerable: bool = False,
    ) -> None:
        self.canned = canned or {}
        self.default = default
        self.simulate_vulnerable = simulate_vulnerable

    def generate_response(self, prompt: str, **_: Any) -> str:
        for needle, reply in self.canned.items():
            if needle in prompt:
                return reply
        if self.simulate_vulnerable:
            return SIMULATED_VULNERABLE_RESPONSE
        return self.default or f"[offline:{len(prompt)}ch]"

    def chat(self, prompt: str, **_: Any) -> LLMResult:
        return LLMResult(text=self.generate_response(prompt), model="offline")

    @property
    def configured(self) -> bool:
        return True
