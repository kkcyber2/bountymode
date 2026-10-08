"""
Target HTTP client — UI scan key ONLY (Operation: Key Isolation).

Universal Bearer-authenticated HTTP for all four kinetic strike vectors.
Brain/strategy uses GROQ_API_KEY / OPENROUTER_API_KEY via clients/llm_client.py.

Handshake policy: ``assert_provider_handshake`` was permanently removed.
Scan-form API keys and URLs are used as-is — no ``gsk_`` / ``sk-`` prefix checks.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import httpx

from forgeguard_bridge import OpenAICompatibleClient

log = logging.getLogger(__name__)

AUTH_FAILURE_MESSAGE = (
    "Authentication Error: Target rejected the provided API Key."
)

# assert_provider_handshake was deleted — never validate gsk_/sk- prefixes or abort
# sovereign (ownership_verified) scans. Keys from the scan form are used as-is.


def assert_provider_handshake(*_args: object, **_kwargs: object) -> None:
    """Permanently removed. No-op so legacy imports cannot crash the engine."""
    return None


def _url_host(target_url: str) -> str:
    return (urlparse(target_url).hostname or "").lower()


def provider_from_url_host(target_url: str) -> str | None:
    host = _url_host(target_url)
    url_lower = (target_url or "").lower()
    if "groq.com" in host or "groq.com" in url_lower:
        return "groq"
    if "openai.com" in host or "api.openai" in host or "openai.com" in url_lower:
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


def _require_user_scan_key(api_key: str) -> str:
    key = (api_key or "").strip()
    if not key:
        raise ValueError("Target API key is empty — provide the key from the scan form.")
    return key


def build_target_authorization(api_key: str, target_provider: str = "") -> str:
    """Universal Bearer header — scan-form key only."""
    return f"Bearer {_require_user_scan_key(api_key)}"


class UniversalTargetClient:
    """
    Universal HTTP client for all kinetic vectors.
    Sends Authorization: Bearer [user_key] on every outbound request.
    """

    def __init__(
        self,
        target_url: str,
        target_api_key: str,
        *,
        model: str = "",
        target_provider: str = "",
        timeout: float = 30.0,
        max_tokens: int = 512,
    ) -> None:
        url = (target_url or "").strip()
        if not url.startswith("http"):
            url = f"https://{url}"
        self.base_url = url.rstrip("/")
        self.api_key = _require_user_scan_key(target_api_key)
        self.model = model or ""
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.target_provider = resolve_target_provider(url, target_provider)
        self._llm_client: Optional[OpenAICompatibleClient] = None

    def authorization_header(self) -> str:
        return f"Bearer {self.api_key}"

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "Authorization": self.authorization_header(),
            "Accept": "*/*",
        }
        if extra:
            headers.update(extra)
        return headers

    def _resolve_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = f"/{path_or_url}"
        return urljoin(self.base_url + "/", path_or_url.lstrip("/"))

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        json: Any = None,
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        url = self._resolve_url(path_or_url)
        with httpx.Client(timeout=timeout or self.timeout, follow_redirects=True) as client:
            return client.request(
                method.upper(),
                url,
                json=json,
                data=data,
                headers=self._headers(headers),
            )

    async def request_async(
        self,
        method: str,
        path_or_url: str,
        *,
        json: Any = None,
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        url = self._resolve_url(path_or_url)
        async with httpx.AsyncClient(
            timeout=timeout or self.timeout, follow_redirects=True
        ) as client:
            return await client.request(
                method.upper(),
                url,
                json=json,
                data=data,
                headers=self._headers(headers),
            )

    def _llm(self) -> OpenAICompatibleClient:
        if self._llm_client is None:
            self._llm_client = OpenAICompatibleClient(
                base_url=self.base_url,
                api_key=self.api_key,
                model=self.model or "gpt-4o-mini",
                timeout=self.timeout,
                max_tokens=self.max_tokens,
            )
            self._llm_client.target_provider = self.target_provider  # type: ignore[attr-defined]
        return self._llm_client

    def chat_completion(self, prompt: str) -> str:
        """LLM vector — OpenAI-compatible chat/completions."""
        return self._llm().generate_response(prompt)

    def generate_response(self, prompt: str) -> str:
        """Alias for Garak/PyRIT probe compatibility."""
        return self.chat_completion(prompt)


def build_universal_client(
    *,
    target_url: str,
    target_api_key: str,
    model: str = "",
    target_provider: str = "",
    timeout: float = 30.0,
    max_tokens: int = 512,
) -> UniversalTargetClient:
    return UniversalTargetClient(
        target_url,
        target_api_key,
        model=model,
        target_provider=target_provider,
        timeout=timeout,
        max_tokens=max_tokens,
    )


def build_target_client(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target_provider: str = "",
    timeout: float = 30.0,
    max_tokens: int = 512,
) -> OpenAICompatibleClient:
    """LLM factory — returns OpenAI-compatible client backed by universal key."""
    utc = build_universal_client(
        target_url=base_url,
        target_api_key=api_key,
        model=model,
        target_provider=target_provider,
        timeout=timeout,
        max_tokens=max_tokens,
    )
    return utc._llm()


def is_auth_failure_response(response: str, http_status: int = 0) -> bool:
    if http_status == 401:
        return True
    text = (response or "").lower()
    return "[http-401]" in text or "invalid api key" in text or "incorrect api key" in text
