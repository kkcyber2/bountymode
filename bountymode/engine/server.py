"""A local HTTP façade over the in-process engine.

Why this exists: :class:`~bountymode.runner.adapter.AgathonAdapter` speaks HTTP
to the engine's scan endpoints, and some deployments want that separation (the
engine on a worker, the workflow layer elsewhere).  This module serves the same
two shapes from *this* repository, so a single-repo deployment still works over
HTTP when the operator asks for it.

Endpoints
---------
``GET  /health``                liveness + catalogue stats
``GET  /bounty/techniques``     the engine's live technique catalogue
``POST /bounty/run-test``       run one technique in-process
``POST /v1/chat/completions``   OpenAI-compatible proxy for the target model

Run it with::

    python -m bountymode.engine.server --port 8088

It is a single-operator local tool: it binds to ``127.0.0.1`` by default, adds
no dependency, and **requires a bearer token by default** -- an ephemeral one is
generated per process unless ``--token``/``$BOUNTYMODE_ENGINE_TOKEN`` supplies
one, and ``--no-auth`` (loopback only) is the explicit opt-out.  Cross-origin
browser requests are refused outright.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from .catalogue import default_catalogue
from .llm import ChatClient, client_from_config
from .local import LocalEngine
from .paths import engine_available

log = logging.getLogger(__name__)

TOKEN_ENV = "BOUNTYMODE_ENGINE_TOKEN"

#: Hosts treated as loopback for the CORS / bind checks.
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def generate_token() -> str:
    """A fresh, unguessable bearer token for one server process."""
    return secrets.token_urlsafe(32)


#: Shared state for the handler; one engine instance per process.
_STATE: Dict[str, Any] = {"engine": None, "token": ""}


def _engine() -> LocalEngine:
    if _STATE["engine"] is None:
        _STATE["engine"] = LocalEngine()
    return _STATE["engine"]


class EngineRequestHandler(BaseHTTPRequestHandler):
    """Minimal JSON handler for the four engine endpoints."""

    server_version = "BountyModeEngine/0.2"

    # -- plumbing ----------------------------------------------------------- #

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        log.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _cors_origin(self) -> str:
        """Echo the ``Origin`` header only when it is a loopback origin.

        The fa\u00e7ade is a local tool: a browser tab on another site must not be
        able to read its responses.  Combined with the bearer-token requirement
        this closes the cross-origin read path.
        """
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return ""
        from urllib.parse import urlparse

        host = (urlparse(origin).hostname or "").lower()
        return origin if host in _LOOPBACK_HOSTS else ""

    def do_OPTIONS(self) -> None:  # noqa: N802
        """Answer a CORS preflight without touching the engine."""
        self.send_response(204)
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, X-Internal-Scan-Token",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorised(self) -> bool:
        # A cross-origin browser request is never authorised, even with a valid
        # token, so another tab cannot drive the local engine.
        origin = (self.headers.get("Origin") or "").strip()
        if origin and not self._cors_origin():
            return False
        required = _STATE["token"]
        if not required:
            return True
        header = self.headers.get("Authorization", "")
        provided = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not provided:
            provided = (self.headers.get("X-Internal-Scan-Token") or "").strip()
        return provided == required

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return {}

    # -- routes ------------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/health":
            self._send(200, {
                "status": "ok",
                "engine_present": engine_available(),
                "catalogue": default_catalogue().stats(),
            })
            return
        if path == "/bounty/techniques":
            if not self._authorised():
                self._send(401, {"error": "unauthorised"})
                return
            cat = default_catalogue()
            self._send(200, {
                "count": len(cat.entries()),
                "families": cat.families(),
                "techniques": cat.describe(),
            })
            return
        self._send(404, {"error": "not found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0].rstrip("/") or "/"
        if not self._authorised():
            self._send(401, {"error": "unauthorised"})
            return

        if path == "/bounty/run-test":
            self._handle_run_test()
            return
        if path == "/v1/chat/completions":
            self._handle_chat()
            return
        self._send(404, {"error": "not found", "path": path})

    def _handle_run_test(self) -> None:
        body = self._body()
        from ..models import Technique

        technique = Technique(
            id=str(body.get("technique") or "unknown"),
            name=str(body.get("technique") or "unknown"),
            engine_key=str(body.get("technique") or ""),
        )
        target = str(body.get("target_url") or "")
        result = _engine().run_technique(technique, target, body.get("params") or None)
        self._send(200, result.__dict__)

    def _handle_chat(self) -> None:
        body = self._body()
        messages = body.get("messages") or []
        prompt = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                prompt = msg.get("content", "") or ""
                break
        client: ChatClient = client_from_config()
        if body.get("model"):
            client.model = body["model"]
        result = client.chat(prompt)
        self._send(200, {
            "id": "bountymode-engine",
            "object": "chat.completion",
            "model": result.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": result.text},
                "finish_reason": "stop",
            }],
            "bountymode": {"ok": result.ok, "error": result.error},
        })


def serve(host: str = "127.0.0.1", port: int = 8088, token: Optional[str] = None) -> None:
    """Start the engine HTTP façade (blocking).

    ``token=None`` (the default) generates an ephemeral bearer token, so the
    server is authenticated unless the caller explicitly passes ``token=""``.
    """
    if token is None:
        token = generate_token()
    _STATE["token"] = token
    httpd = ThreadingHTTPServer((host, port), EngineRequestHandler)
    log.info("engine façade listening on http://%s:%d (auth=%s)", host, port, bool(token))
    print(f"Bounty Mode engine façade on http://{host}:{port}  (auth={'on' if token else 'off'})")
    if token:
        print(f"  bearer token: {token}")
        print(f"  send it as:   Authorization: Bearer {token}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def _parse_args(argv: Optional[list] = None) -> Tuple[str, int, str]:
    p = argparse.ArgumentParser(prog="python -m bountymode.engine.server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8088)
    p.add_argument("--token", default=os.environ.get(TOKEN_ENV, ""))
    p.add_argument("--no-auth", action="store_true",
                   help="explicitly run without a token (loopback only)")
    args = p.parse_args(argv)
    if args.no_auth:
        if args.host not in _LOOPBACK_HOSTS:
            raise SystemExit("--no-auth is only allowed on a loopback address")
        return args.host, args.port, ""
    # Default to an ephemeral token: the server is authenticated unless the
    # operator explicitly opts out with --no-auth.
    token = (args.token or "").strip() or generate_token()
    return args.host, args.port, token


def main(argv: Optional[list] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    host, port, token = _parse_args(argv)
    serve(host=host, port=port, token=token)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
