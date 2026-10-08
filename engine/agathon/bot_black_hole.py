"""
Black-Hole bot defense — streams zero bytes to scraper User-Agents.

Targets: python-requests, scrapy, puppeteer (case-insensitive substring match).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import AsyncIterator, Callable, Optional

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import StreamingResponse

log = logging.getLogger("agathon.black_hole")

BLACK_HOLE_UA_MARKERS = ("python-requests", "scrapy", "puppeteer")
BLACK_HOLE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB
STREAM_CHUNK_BYTES = 256 * 1024  # 256 KiB per chunk
PROBE_EXEMPT_PATHS = frozenset({"/health", "/healthz"})


def _internal_scan_token() -> str:
    return (
        os.environ.get("INTERNAL_SCAN_TOKEN")
        or os.environ.get("AGATHON_INTERNAL_SECRET")
        or ""
    ).strip()


def is_probe_exempt(request: Request) -> bool:
    """Skip Black-Hole for liveness probes and ForgeGuard/Vercel health checks."""
    if request.url.path in PROBE_EXEMPT_PATHS:
        return True

    if (request.headers.get("x-internal-scan-token") or "").strip():
        return True

    expected = _internal_scan_token()
    auth = (request.headers.get("authorization") or "").strip()
    if expected and auth.lower().startswith("bearer "):
        if auth[7:].strip() == expected:
            return True

    ua = (request.headers.get("user-agent") or "").lower()
    if "forgeguard" in ua:
        return True

    return False


def is_blackhole_bot(user_agent: Optional[str]) -> bool:
    ua = (user_agent or "").lower()
    if not ua:
        return False
    return any(marker in ua for marker in BLACK_HOLE_UA_MARKERS)


def _client_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _post_attack_log_sync(request: Request, user_agent: str) -> None:
    url = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
    key = (os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
    if not url or not key:
        return

    row = {
        "ip_address": _client_ip(request),
        "path": request.url.path,
        "method": request.method,
        "user_agent": user_agent,
        "reason": "black_hole_bot",
        "metadata": {
            "severity": "CRITICAL",
            "defense": "black_hole",
            "bytes_planned": BLACK_HOLE_BYTES,
        },
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(
                f"{url}/rest/v1/attack_logs",
                json=row,
                headers={
                    "apikey": key,
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
            if resp.status_code >= 400:
                log.warning(
                    "[black_hole] attack_logs insert HTTP %s: %s",
                    resp.status_code,
                    resp.text[:200],
                )
    except Exception as exc:  # noqa: BLE001
        log.warning("[black_hole] attack_logs insert failed: %s", exc)


async def log_blackhole_breach(request: Request, user_agent: str) -> None:
    await asyncio.to_thread(_post_attack_log_sync, request, user_agent)


async def zero_byte_stream() -> AsyncIterator[bytes]:
    chunk = b"\x00" * STREAM_CHUNK_BYTES
    sent = 0
    while sent < BLACK_HOLE_BYTES:
        yield chunk
        sent += len(chunk)


class BotBlackHoleMiddleware(BaseHTTPMiddleware):
    """Return a 10 GiB zero stream instead of 4xx/5xx for known scraper UAs."""

    async def dispatch(self, request: Request, call_next):
        if is_probe_exempt(request):
            return await call_next(request)

        ua = request.headers.get("user-agent") or ""
        if not is_blackhole_bot(ua):
            return await call_next(request)

        log.info(
            "[black_hole] Engaging Black-Hole defense ua=%s path=%s ip=%s",
            ua[:120],
            request.url.path,
            _client_ip(request),
        )
        asyncio.create_task(log_blackhole_breach(request, ua))

        return StreamingResponse(
            zero_byte_stream(),
            status_code=200,
            media_type="application/octet-stream",
            headers={
                "Content-Length": str(BLACK_HOLE_BYTES),
                "Cache-Control": "no-store",
                "X-Aegis-Black-Hole": "1",
                "X-ForgeGuard-Defense": "black-hole",
            },
        )


def install_bot_black_hole(app) -> None:
    app.add_middleware(BotBlackHoleMiddleware)
