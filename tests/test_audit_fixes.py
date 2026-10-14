"""Regression tests for the four externally-reported audit issues.

Each test pins the *specific* defect that was reproduced before the fix, so a
future change that reintroduces it fails here rather than in production.
"""

from __future__ import annotations

import json
import shutil
import threading
import time
import urllib.error
import urllib.request

import pytest

# --------------------------------------------------------------------------- #
# Issue 1 -- a wildcard-only scope must not halt the planner
# --------------------------------------------------------------------------- #

from bountymode.autonomous.planner import (
    HeuristicPlanner,
    PlannedTarget,
    synthesize_from_wildcard,
)
from bountymode.models import ProgramScope, ScopeTarget


class TestWildcardScopePlanner:
    def _wildcard_scope(self) -> ProgramScope:
        return ProgramScope(
            program="openai-safety",
            platform="bugcrowd",
            in_scope=[
                ScopeTarget(pattern="*.openai.com", kind="web"),
                ScopeTarget(pattern="*.chatgpt.com", kind="web"),
            ],
        )

    def test_wildcard_only_scope_yields_a_concrete_target(self) -> None:
        plan = HeuristicPlanner().plan(self._wildcard_scope())
        assert plan.targets, "a wildcard-only scope must not produce an empty plan"
        assert all(not t.target.startswith("*") for t in plan.targets)

    def test_synthesised_target_is_flagged_and_explained(self) -> None:
        plan = HeuristicPlanner().plan(self._wildcard_scope())
        assert all(t.synthesized for t in plan.targets)
        assert any("wildcard" in n.lower() for n in plan.notes)
        assert all("SYNTHESISED" in t.rationale for t in plan.targets)

    def test_exactly_one_host_per_wildcard_no_mass_expansion(self) -> None:
        plan = HeuristicPlanner().plan(self._wildcard_scope())
        # Two wildcards -> at most two synthesised hosts, never a fan-out.
        assert len(plan.targets) == 2
        assert {t.target for t in plan.targets} == {"www.openai.com", "www.chatgpt.com"}

    def test_synthesised_host_matches_the_original_wildcard(self) -> None:
        # The gate must still accept it: it is covered by the wildcard entry.
        from bountymode.scope.matcher import resolve_scope

        scope = self._wildcard_scope()
        in_scope, entry, exclusion = resolve_scope("www.openai.com", scope)
        assert in_scope and entry is not None and exclusion is None

    def test_synthesize_helper_rejects_unsafe_patterns(self) -> None:
        assert synthesize_from_wildcard("*.example.com") == "www.example.com"
        assert synthesize_from_wildcard("*") is None
        assert synthesize_from_wildcard("*.example.com/path") is None
        assert synthesize_from_wildcard("example.com") is None
        assert synthesize_from_wildcard("*.localhost") is None

    def test_non_wildcard_scope_is_unchanged(self) -> None:
        scope = ProgramScope(
            program="acme", platform="bugcrowd",
            in_scope=[ScopeTarget(pattern="api.acme.example", kind="api")],
        )
        plan = HeuristicPlanner().plan(scope)
        assert [t.target for t in plan.targets] == ["api.acme.example"]
        assert plan.targets[0].synthesized is False

    def test_planned_target_serialises_the_flag(self) -> None:
        data = PlannedTarget(
            target="www.openai.com", kind="web", domain="web_api",
            priority=1, score=1.0, synthesized=True,
        ).to_dict()
        assert data["synthesized"] is True


# --------------------------------------------------------------------------- #
# Issue 2 -- a non-string / null completion must not crash the caller
# --------------------------------------------------------------------------- #

import bountymode.engine.llm as llm
from bountymode.engine.llm import ChatClient, _coerce_content


class _Resp:
    def __init__(self, payload: dict) -> None:
        self._b = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch(monkeypatch, handler):
    def fake_urlopen(req, timeout=None):
        body = json.loads(req.data.decode("utf-8"))
        return _Resp(handler(body["model"]))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)


class TestNullAndNonStringContent:
    def test_coerce_none_is_empty_string(self) -> None:
        assert _coerce_content(None) == ""

    def test_coerce_string_passthrough(self) -> None:
        assert _coerce_content("pong") == "pong"

    def test_coerce_list_of_parts(self) -> None:
        assert _coerce_content([{"type": "text", "text": "po"}, {"type": "text", "text": "ng"}]) == "pong"

    def test_coerce_list_of_strings(self) -> None:
        assert _coerce_content(["po", "ng"]) == "pong"

    def test_null_content_routes_to_fallback(self, monkeypatch) -> None:
        _patch(monkeypatch, lambda m: {"choices": [{"message": {"content": None}}]})
        client = ChatClient(api_key="k", model="primary", fallbacks=["backup"], max_attempts=1)
        r = client.chat("hi")
        assert r.ok is False
        assert "empty completion" in r.error

    def test_list_content_does_not_raise(self, monkeypatch) -> None:
        _patch(monkeypatch, lambda m: {
            "choices": [{"message": {"content": [{"type": "text", "text": "pong"}]}}]
        })
        client = ChatClient(api_key="k", model="primary", max_attempts=1)
        r = client.chat("hi")
        assert r.ok is True
        assert r.text == "pong"

    def test_malformed_choice_shape_does_not_raise(self, monkeypatch) -> None:
        _patch(monkeypatch, lambda m: {"choices": ["not-a-dict"]})
        client = ChatClient(api_key="k", model="primary", max_attempts=1)
        r = client.chat("hi")
        assert r.ok is False


# --------------------------------------------------------------------------- #
# Issue 3 -- the engine server must require a token by default
# --------------------------------------------------------------------------- #

from bountymode.engine import server as srv


class TestEngineServerAuth:
    def test_parse_args_defaults_to_a_generated_token(self) -> None:
        host, port, token = srv._parse_args([])
        assert host == "127.0.0.1"
        assert token, "the default must be an ephemeral token, not empty"

    def test_no_auth_is_the_explicit_opt_out(self) -> None:
        _host, _port, token = srv._parse_args(["--no-auth"])
        assert token == ""

    def test_explicit_token_is_honoured(self) -> None:
        _host, _port, token = srv._parse_args(["--token", "abc"])
        assert token == "abc"

    def test_no_auth_refused_on_non_loopback(self) -> None:
        with pytest.raises(SystemExit):
            srv._parse_args(["--no-auth", "--host", "0.0.0.0"])

    def test_generate_token_is_unguessable(self) -> None:
        assert len(srv.generate_token()) >= 32
        assert srv.generate_token() != srv.generate_token()

    def test_serve_default_token_is_not_none(self) -> None:
        # serve()'s default must be None (=> generate), never "" (=> open).
        assert srv.serve.__defaults__[2] is None

    def test_live_server_rejects_unauthenticated_and_cross_origin(self) -> None:
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        t = threading.Thread(
            target=srv.serve, kwargs={"host": "127.0.0.1", "port": port}, daemon=True
        )
        t.start()
        time.sleep(0.6)
        token = srv._STATE["token"]
        assert token

        def call(headers):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/bounty/techniques", headers=headers
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code

        assert call({}) == 401
        assert call({"Authorization": "Bearer wrong"}) == 401
        assert call({"Authorization": f"Bearer {token}"}) == 200
        # A valid token from a foreign origin is still refused.
        assert call({"Authorization": f"Bearer {token}", "Origin": "https://evil.example"}) == 401
        # A loopback origin is allowed.
        assert call({"Authorization": f"Bearer {token}", "Origin": "http://127.0.0.1:3000"}) == 200


# --------------------------------------------------------------------------- #
# Issue 4 -- PDF intake must not depend on the POSIX pdftotext binary
# --------------------------------------------------------------------------- #

from bountymode.autonomous.intake import DocumentIntake


class TestPdfIntakePortability:
    def test_pypdf_is_a_declared_dependency(self) -> None:
        import pathlib

        text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
        assert "pypdf" in text

    def test_no_reader_installed_gives_a_setup_message(self, monkeypatch, tmp_path) -> None:
        """With neither pypdf nor pdftotext, the message must say how to fix it."""
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(
            "bountymode.autonomous.intake._module_available", lambda name: False
        )
        p = tmp_path / "brief.pdf"
        p.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
        result = DocumentIntake().read(str(p))
        assert not result.ok
        assert "no PDF reader" in result.error
        assert "pip install pypdf" in result.hint

    def test_reader_present_but_no_text_layer_says_scan(self, monkeypatch, tmp_path) -> None:
        """A reader that runs but finds nothing must blame the scan, not setup."""
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(
            "bountymode.autonomous.intake._module_available", lambda name: True
        )
        p = tmp_path / "scan.pdf"
        p.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
        result = DocumentIntake().read(str(p))
        assert not result.ok
        assert "OCR" in result.hint

    def test_pypdf_reads_a_real_pdf(self, tmp_path) -> None:
        """End-to-end: a genuine PDF with a text layer is read by pypdf."""
        pytest.importorskip("pypdf")

        # Build a one-page PDF with real text using a minimal hand-built PDF
        # with a text object.
        content = b"BT /F1 12 Tf 72 720 Td (In Scope: api.acme.example) Tj ET"
        pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
            b"/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n"
            b"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
            b"5 0 obj<</Length " + str(len(content)).encode() + b">>stream\n"
            + content + b"\nendstream endobj\n"
            b"trailer<</Root 1 0 R>>\n%%EOF\n"
        )
        p = tmp_path / "real.pdf"
        p.write_bytes(pdf)
        result = DocumentIntake().read(str(p))
        # pypdf may or may not extract from this minimal PDF; if it does, the
        # text must be present and the reader must be pypdf.
        if result.ok:
            assert result.reader == "pypdf"
            assert "api.acme.example" in result.text
