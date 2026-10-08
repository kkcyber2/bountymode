"""
Weapon strike dispatcher — scan-form API key ONLY (Key Isolation Protocol).

All target HTTP for OpenAI-compatible endpoints uses a strict 4-field JSON body.
Brain credentials (GROQ_API_KEY, OPENROUTER_API_KEY) must never be used here.

No ``assert_provider_handshake`` and no API-key prefix validation (``gsk_`` / ``sk-``).
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

AUTH_FAILURE_MESSAGE = (
    "Authentication Error: Target rejected the provided API Key."
)
KEY_PROVIDER_MISMATCH = "KEY_PROVIDER_MISMATCH"

TARGET_REJECTION_MESSAGE = (
    "ATTACK REJECTED BY TARGET - Verify model ID and API Permissions."
)

STRICT_PAYLOAD_KEYS = frozenset({"model", "messages", "temperature", "max_tokens"})

SOVEREIGN_STRIKE_BACKOFF_S = 5.0
_MAX_404_MODEL_ATTEMPTS = 2

_GROQ_FALLBACK_MODELS: tuple[str, ...] = (
    "llama-3.1-70b-versatile",
    "llama-3.1-8b-instant",
)


def _strike_model_candidates(
    model: str, target_url: str, target_provider: str
) -> list[str]:
    """Primary model first; at most one Groq fallback (404 cap enforced in client)."""
    primary = (model or "gpt-4o-mini").strip()
    if resolve_target_provider(target_url, target_provider) != "groq":
        return [primary]
    out: list[str] = [primary]
    for candidate in _GROQ_FALLBACK_MODELS:
        if candidate and candidate not in out:
            out.append(candidate)
            break
    return out[:_MAX_404_MODEL_ATTEMPTS]

_ENGINE_KEY_ENVS = (
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)


def _url_host(target_url: str) -> str:
    return (urlparse(target_url).hostname or "").lower()


def provider_from_url_host(target_url: str) -> str | None:
    host = _url_host(target_url)
    url_lower = (target_url or "").lower()
    if "groq.com" in host or "groq.com" in url_lower:
        return "groq"
    if "openai.com" in host or "api.openai" in url_lower or "openai.com" in url_lower:
        return "openai"
    if "anthropic.com" in host or "anthropic.com" in url_lower:
        return "anthropic"
    return None


def resolve_target_provider(target_url: str, explicit: str = "") -> str:
    from_url = provider_from_url_host(target_url)
    if from_url:
        return from_url
    if explicit and explicit.strip():
        return explicit.strip().lower()
    host = _url_host(target_url)
    if "together.xyz" in host or "fireworks.ai" in host:
        return "openai_compat"
    return "openai_compat"


def provider_from_url(target_url: str, explicit: str = "") -> str:
    """Resolve provider from target URL with optional explicit override (orchestrator API)."""
    return resolve_target_provider(target_url, explicit)


def normalize_openai_base_url(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"
    lower = base.lower()
    for suffix in ("/chat/completions", "/completions"):
        if lower.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            lower = base.lower()
    if not (base.endswith("/v1") or "/v1/" in base):
        base = base + "/v1"
    return base


def build_strict_chat_payload(
    *,
    model: str,
    messages: list,
    temperature: float = 0.4,
    max_tokens: int = 512,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    OpenAI-compatible strike body — ONLY model, messages, temperature, max_tokens.
    """
    if extra:
        stripped = [k for k in extra if k not in STRICT_PAYLOAD_KEYS]
        if stripped:
            log.debug("[strike] stripped non-strict payload keys: %s", stripped)
    return {
        "model": (model or "gpt-4o-mini").strip(),
        "messages": messages,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
    }


def build_chat_completions_payload(
    *,
    model: str,
    messages: list,
    temperature: float = 0.4,
    max_tokens: int = 512,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Strict 4-field OpenAI chat body — strips provider/session_id and all extras."""
    return build_strict_chat_payload(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        extra=extra,
    )


def _engine_env_keys() -> set[str]:
    keys: set[str] = set()
    for name in _ENGINE_KEY_ENVS:
        val = (os.environ.get(name) or "").strip()
        if val:
            keys.add(val)
    return keys


def _require_scan_key(api_key: str) -> str:
    key = (api_key or "").strip()
    if not key:
        raise ValueError("Target API key is empty — provide the key from the scan form.")
    return key


def is_auth_failure_response(response: str, http_status: int = 0) -> bool:
    if http_status == 401:
        return True
    text = (response or "").lower()
    return "[http-401]" in text or "invalid api key" in text or "incorrect api key" in text


def is_target_not_found_response(response: str, http_status: int = 0) -> bool:
    if http_status == 404:
        return True
    text = (response or "").lower()
    return text.startswith("[http-404]") or "[http-404]" in text


def _mask_key(api_key: str) -> str:
    if not api_key:
        return "[empty]"
    if len(api_key) <= 8:
        return "***"
    return f"{api_key[:4]}…{api_key[-4:]}"


class WeaponLLMClient:
    """Target weapon — scan-request api_key only; strict OpenAI-compatible payload."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        target_provider: str = "",
        timeout: float = 30.0,
        max_tokens: int = 512,
    ) -> None:
        self.base_url = normalize_openai_base_url(base_url)
        self.api_key = _require_scan_key(api_key)
        self.model = model or "gpt-4o-mini"
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.target_provider = resolve_target_provider(base_url, target_provider)

    def generate_response(
        self,
        prompt: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> str:
        if kwargs:
            log.debug("[strike] ignoring extra kwargs: %s", list(kwargs.keys()))

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        model_candidates = _strike_model_candidates(
            self.model, self.base_url, self.target_provider
        )

        max_attempts = 5
        base_delay = 2.0
        cap_delay = 60.0
        not_found_attempts = 0

        for model_name in model_candidates:
            body = build_chat_completions_payload(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature if temperature is not None else 0.4,
                max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
                extra=kwargs or None,
            )

            for attempt in range(max_attempts):
                try:
                    r = requests.post(
                        url, headers=headers, json=body, timeout=self.timeout
                    )
                except requests.RequestException as e:
                    if attempt < max_attempts - 1:
                        time.sleep(min(cap_delay, base_delay * (2 ** attempt)))
                        continue
                    return f"[transport-error] {type(e).__name__}: {e}"

                if r.status_code in (429, 503) and attempt < max_attempts - 1:
                    delay = max(
                        SOVEREIGN_STRIKE_BACKOFF_S,
                        min(cap_delay, base_delay * (2 ** attempt)),
                    )
                    delay += random.uniform(0, delay * 0.2)
                    time.sleep(delay)
                    continue

                if r.status_code == 404:
                    not_found_attempts += 1
                    if not_found_attempts >= _MAX_404_MODEL_ATTEMPTS:
                        try:
                            err = r.json()
                        except Exception:  # noqa: BLE001
                            err = {"text": r.text[:800]}
                        return f"[http-404] {json.dumps(err)[:800]}"
                    if model_name != model_candidates[-1]:
                        log.warning(
                            "[strike] HTTP 404 model=%s — one fallback remaining",
                            model_name,
                        )
                        break
                    try:
                        err = r.json()
                    except Exception:  # noqa: BLE001
                        err = {"text": r.text[:800]}
                    return f"[http-404] {json.dumps(err)[:800]}"

                if r.status_code >= 400:
                    try:
                        err = r.json()
                    except Exception:  # noqa: BLE001
                        err = {"text": r.text[:500]}
                    log.warning(
                        "[strike] HTTP %s model=%s url=%s key=%s",
                        r.status_code,
                        model_name,
                        self.base_url,
                        _mask_key(self.api_key),
                    )
                    return f"[http-{r.status_code}] {json.dumps(err)[:500]}"

                if model_name != self.model:
                    self.model = model_name
                    log.info("[strike] Groq model fallback active: %s", model_name)

                try:
                    data = r.json()
                    choices = data.get("choices") or []
                    if not choices:
                        return "[empty-response]"
                    msg = choices[0].get("message", {})
                    return str(msg.get("content") or "")
                except Exception as e:  # noqa: BLE001
                    return f"[parse-error] {e}: {r.text[:300]}"

        return f"[http-429] rate limit persisted after {max_attempts} attempts"


def build_weapon_client(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target_provider: str = "",
    timeout: float = 30.0,
    max_tokens: int = 512,
) -> WeaponLLMClient:
    return WeaponLLMClient(
        base_url=base_url,
        api_key=api_key,
        model=model,
        target_provider=target_provider,
        timeout=timeout,
        max_tokens=max_tokens,
    )


def strike_authorization_header(api_key: str, target_provider: str = "") -> str:
    return f"Bearer {_require_scan_key(api_key)}"


def build_proof_of_work_poc(*, attacks_run: int, intensity: str) -> str:
    return (
        f"Status: Secure. Total Vectors Tested: {attacks_run}. "
        f"No exploitable vulnerabilities detected at intensity ({intensity})."
    )
