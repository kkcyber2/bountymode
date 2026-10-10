"""Tests for the ChatClient fallback chain and reasoning stripping.

These exercise the live-path fixes without any network: ``urlopen`` is
monkeypatched to return canned OpenAI-compatible payloads.
"""

from __future__ import annotations

import io
import json
import urllib.error

from bountymode.engine.llm import ChatClient, _strip_reasoning


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _completion(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _patch_urlopen(monkeypatch, handler):
    """handler(model) -> dict payload, or raises."""
    import bountymode.engine.llm as llm

    def fake_urlopen(req, timeout=None):
        body = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(handler(body["model"]))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)


# -- fallback chain --------------------------------------------------------- #

def test_chat_returns_primary_when_it_answers(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion("pong"))
    client = ChatClient(api_key="k", model="primary", fallbacks=["backup"])
    r = client.chat("hi")
    assert r.ok and r.text == "pong" and r.model == "primary"


def test_chat_falls_back_when_primary_returns_empty(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion("" if m == "primary" else "pong"))
    client = ChatClient(api_key="k", model="primary", fallbacks=["backup"])
    r = client.chat("hi")
    assert r.ok and r.text == "pong" and r.model == "backup"


def test_chat_falls_back_when_primary_errors(monkeypatch):
    import bountymode.engine.llm as llm

    def fake_urlopen(req, timeout=None):
        body = json.loads(req.data.decode("utf-8"))
        if body["model"] == "primary":
            raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, io.BytesIO(b""))
        return _FakeResponse(_completion("pong"))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    client = ChatClient(api_key="k", model="primary", fallbacks=["backup"], max_attempts=1)
    r = client.chat("hi")
    assert r.ok and r.model == "backup"


def test_chat_reports_failure_when_all_candidates_fail(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion(""))
    client = ChatClient(api_key="k", model="primary", fallbacks=["backup"])
    r = client.chat("hi")
    assert r.ok is False
    assert "empty completion" in r.error


def test_chat_empty_content_is_not_ok(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion(""))
    client = ChatClient(api_key="k", model="primary")
    r = client.chat("hi")
    assert r.ok is False and r.text == ""


def test_chat_without_fallbacks_does_not_walk(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion("" if m == "primary" else "pong"))
    client = ChatClient(api_key="k", model="primary", fallbacks=["backup"])
    r = client.chat("hi", allow_fallback=False)
    assert r.ok is False


# -- reachability probe ----------------------------------------------------- #

def test_reachable_does_not_use_fallbacks(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion("" if m == "primary" else "pong"))
    client = ChatClient(api_key="k", model="primary", fallbacks=["backup"])
    probe = client.reachable()
    assert probe.ok is False
    assert "empty completion" in probe.error


def test_reachable_ok_on_real_content(monkeypatch):
    _patch_urlopen(monkeypatch, lambda m: _completion("pong"))
    client = ChatClient(api_key="k", model="primary")
    assert client.reachable().ok is True


def test_reachable_without_key_is_not_ok():
    client = ChatClient(api_key="", model="primary")
    probe = client.reachable()
    assert probe.ok is False
    assert "no API key" in probe.error


# -- reasoning stripping ---------------------------------------------------- #

def test_strip_reasoning_removes_tagged_block():
    assert _strip_reasoning(" thinkinghmm</think>pong") == "pong"


def test_strip_reasoning_removes_untagged_preamble():
    text = "Here's a thinking process:\n\n1. analyze\n2. decide\n\nThe answer is pong."
    assert _strip_reasoning(text) == "1. analyze\n2. decide\n\nThe answer is pong."


def test_strip_reasoning_leaves_plain_text_alone():
    assert _strip_reasoning("pong") == "pong"


def test_strip_reasoning_keeps_single_paragraph_opener():
    # A lone opener with no following paragraph must not be emptied.
    assert _strip_reasoning("Here's a thinking process:") == "Here's a thinking process:"
