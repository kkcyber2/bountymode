"""Regression tests for the web engine, the web oracle, and the scope fix.

These pin the bugs found during live hard-testing:

* the ``web_api`` domain had no engine at all (every technique was skipped and the
  scan still reported PASS);
* ``host:port`` scope entries were silently dropped by the extractor;
* single-payload probes produced false negatives against a WAF;
* the XSS judge only recognised ``<script>``;
* the web oracle was never selected for a web finding.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bountymode.engine.web import (
    HttpProbe,
    HttpResult,
    WebEngine,
    _judge_rate_limit,
    _judge_xss,
    build_web_dispatch,
    supported_techniques,
)
from bountymode.models import Technique
from bountymode.program import ProgramImporter
from bountymode.verify.oracles import web_oracle
from bountymode.verify.web_oracles import WEB_CATEGORIES, WebDifferentialOracle


# --------------------------------------------------------------------------- #
# a tiny in-process target
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    """A minimal target: vulnerable on ``/vuln``, clean on ``/safe``."""

    def log_message(self, *a):  # silence
        pass

    def _send(self, code: int, body: str, headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/vuln"):
            self._send(200, "<html><body><div><script>alert(1)</script></div></body></html>")
        elif self.path.startswith("/safe"):
            self._send(200, "<html><body><div>hello world</div></body></html>")
        elif self.path.startswith("/health"):
            self._send(200, '{"status":"ok"}')
        else:
            self._send(404, "not found")


@pytest.fixture(scope="module")
def target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"127.0.0.1:{port}"
    server.shutdown()


# --------------------------------------------------------------------------- #
# the engine exists and covers the web domain
# --------------------------------------------------------------------------- #

def test_web_engine_covers_every_web_technique():
    """Every web_api technique must have a real probe, not a silent skip."""
    from bountymode.domains import DEFAULT_REGISTRY

    adapter = DEFAULT_REGISTRY.get("web_api")
    ids = {t.id for t in adapter.techniques()}
    missing = ids - set(supported_techniques())
    assert not missing, f"web techniques with no engine probe: {sorted(missing)}"


def test_unknown_technique_is_unavailable_not_a_crash():
    engine = WebEngine("127.0.0.1:1")
    result = engine.run_technique(Technique(id="nope", name="Nope", category="x"), "127.0.0.1:1")
    assert result.unavailable and not result.success


def test_transport_failure_is_errored_not_raised():
    engine = WebEngine("127.0.0.1:1", timeout=0.5)
    result = engine.run_technique(
        Technique(id="xss", name="XSS", category="xss"), "127.0.0.1:1"
    )
    assert result.errored and not result.success


def test_write_probe_disabled_when_writes_are_off():
    engine = WebEngine("127.0.0.1:1", allow_writes=False)
    tech = Technique(id="mass_assignment", name="Mass Assignment",
                     category="mass_assignment", side_effects=True)
    result = engine.run_technique(tech, "127.0.0.1:1")
    assert result.unavailable and "write probe disabled" in result.evidence


# --------------------------------------------------------------------------- #
# the XSS judge recognises more than <script>
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
])
def test_xss_judge_accepts_event_handler_vectors(payload):
    test = HttpResult(role="test", status=200, body=f"<div>{payload}</div>")
    control = HttpResult(role="control", status=200, body="<div>hello</div>")
    fired, score, _ = _judge_xss(test, control)
    assert fired and score > 0


def test_xss_judge_rejects_plain_text():
    test = HttpResult(role="test", status=200, body="<div>hello world</div>")
    control = HttpResult(role="control", status=200, body="<div>hello</div>")
    fired, _, _ = _judge_xss(test, control)
    assert not fired


# --------------------------------------------------------------------------- #
# the rate-limit judge is a real differential
# --------------------------------------------------------------------------- #

def test_rate_limit_judge_fires_only_without_throttling():
    burst = HttpResult(role="test", status=200, body="{}", statuses=[200] * 8)
    control = HttpResult(role="control", status=200, body="{}")
    fired, _, _ = _judge_rate_limit(burst, control)
    assert fired


def test_rate_limit_judge_declines_when_throttled():
    burst = HttpResult(role="test", status=429, body="{}", statuses=[200, 200, 429, 429])
    control = HttpResult(role="control", status=200, body="{}")
    fired, _, evidence = _judge_rate_limit(burst, control)
    assert not fired and "throttled" in evidence


# --------------------------------------------------------------------------- #
# the web oracle is selected for a web finding
# --------------------------------------------------------------------------- #

def test_web_oracle_claims_the_web_categories():
    oracle = web_oracle()
    assert isinstance(oracle, WebDifferentialOracle)
    for category in WEB_CATEGORIES:
        assert oracle.matches(category, category), category


def test_web_oracle_does_not_claim_prompt_injection():
    """A prompt-injection finding must keep its prompt-shaped oracle."""
    assert not web_oracle().matches("prompt_injection", "prompt_injection")


def test_verifier_honours_an_explicit_oracle():
    from bountymode.verify.engine import GenericVerifier

    explicit = web_oracle()
    verifier = GenericVerifier(attempts=1, oracle=explicit)
    assert verifier.oracle is explicit


# --------------------------------------------------------------------------- #
# the scope extractor accepts host:port and IPv4
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("line,expected", [
    ("| 127.0.0.1:9099 | web |", "127.0.0.1:9099"),
    ("- 127.0.0.1:9099", "127.0.0.1:9099"),
    ("127.0.0.1:9099", "127.0.0.1:9099"),
    ("| api.example.com:8443 | api |", "api.example.com:8443"),
    ("| api.example.com | api |", "api.example.com"),
])
def test_scope_imports_hostport_and_ipv4(line, expected):
    imp = ProgramImporter().import_text("## In Scope\n" + line + "\n")
    patterns = [x.pattern for x in imp.scope.in_scope]
    assert expected in patterns, patterns


def test_scope_still_rejects_platform_hosts():
    imp = ProgramImporter().import_text("## In Scope\n- bugcrowd.com\n")
    assert not [x for x in imp.scope.in_scope if "bugcrowd" in x.pattern]
